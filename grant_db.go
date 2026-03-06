package main

import (
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteGrantStore wraps an InMemoryGrantStore with SQLite persistence.
// Policy grants go to memory only. DeClaw grants go to both memory and DB.
type SQLiteGrantStore struct {
	mem *InMemoryGrantStore
	db  *sql.DB
}

// NewSQLiteGrantStore opens (or creates) a SQLite DB at the given path,
// creates the grants table if needed, loads persisted declaw grants into
// memory, and purges any that have expired.
func NewSQLiteGrantStore(dbPath string) (*SQLiteGrantStore, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// Enable WAL mode for better concurrency
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("set WAL mode: %w", err)
	}

	// Create table
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS grants (
			id          TEXT PRIMARY KEY,
			type        TEXT NOT NULL,
			domain      TEXT,
			path_prefix TEXT,
			method      TEXT,
			url         TEXT,
			granted_at  DATETIME NOT NULL,
			duration_s  INTEGER NOT NULL DEFAULT 0,
			expires_at  DATETIME,
			one_shot    INTEGER NOT NULL DEFAULT 0,
			source      TEXT NOT NULL,
			signature   BLOB
		)
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create table: %w", err)
	}

	// Migration: add signature column if not present (idempotent)
	db.Exec("ALTER TABLE grants ADD COLUMN signature BLOB")

	// Create used_literals table for tracking consumed one-shot grants
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS used_literals (
			id          TEXT PRIMARY KEY,
			type        TEXT NOT NULL,
			domain      TEXT,
			path_prefix TEXT,
			method      TEXT,
			url         TEXT,
			granted_at  DATETIME NOT NULL,
			duration_s  INTEGER NOT NULL DEFAULT 0,
			expires_at  DATETIME,
			source      TEXT NOT NULL,
			signature   BLOB,
			used_at     DATETIME NOT NULL
		)
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create used_literals table: %w", err)
	}

	s := &SQLiteGrantStore{
		mem: NewInMemoryGrantStore(),
		db:  db,
	}

	// Purge expired grants from DB
	if _, err := db.Exec(
		"DELETE FROM grants WHERE expires_at IS NOT NULL AND expires_at < ?",
		time.Now().UTC(),
	); err != nil {
		db.Close()
		return nil, fmt.Errorf("purge expired grants: %w", err)
	}

	// Load remaining grants into memory
	if err := s.loadFromDB(); err != nil {
		db.Close()
		return nil, fmt.Errorf("load grants: %w", err)
	}

	return s, nil
}

func (s *SQLiteGrantStore) loadFromDB() error {
	rows, err := s.db.Query(`
		SELECT id, type, domain, path_prefix, method, url,
		       granted_at, duration_s, expires_at, one_shot, source, signature
		FROM grants
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var g Grant
		var domain, pathPrefix, method, url sql.NullString
		var expiresAt sql.NullTime
		var durationSec int64
		var oneShot int
		var signature []byte

		if err := rows.Scan(
			&g.ID, &g.Type, &domain, &pathPrefix, &method, &url,
			&g.GrantedAt, &durationSec, &expiresAt, &oneShot, &g.Source, &signature,
		); err != nil {
			return fmt.Errorf("scan row: %w", err)
		}

		g.Domain = domain.String
		g.PathPrefix = pathPrefix.String
		g.Method = method.String
		g.URL = url.String
		g.Duration = time.Duration(durationSec) * time.Second
		if expiresAt.Valid {
			g.ExpiresAt = expiresAt.Time
		}
		g.OneShot = oneShot != 0
		g.Signature = signature

		grant := g // copy
		s.mem.Add(&grant)
	}
	return rows.Err()
}

// Add adds a grant to the in-memory store. If the grant is from DeClaw,
// it is also persisted to SQLite.
func (s *SQLiteGrantStore) Add(grant *Grant) {
	s.mem.Add(grant)

	if grant.Source != "policy" {
		s.insertDB(grant)
	}
}

func (s *SQLiteGrantStore) insertDB(g *Grant) {
	var expiresAt *time.Time
	if !g.ExpiresAt.IsZero() {
		t := g.ExpiresAt.UTC()
		expiresAt = &t
	}

	durationSec := int64(g.Duration / time.Second)
	oneShot := 0
	if g.OneShot {
		oneShot = 1
	}

	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO grants
		(id, type, domain, path_prefix, method, url, granted_at, duration_s, expires_at, one_shot, source, signature)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		g.ID, g.Type,
		nullStr(g.Domain), nullStr(g.PathPrefix), nullStr(g.Method), nullStr(g.URL),
		g.GrantedAt.UTC(), durationSec, expiresAt, oneShot, g.Source, g.Signature,
	)
	if err != nil {
		slog.Error("failed to persist grant", "grant_id", g.ID, "error", err)
	}
}

// Remove removes a grant from memory and from the DB.
func (s *SQLiteGrantStore) Remove(id string) {
	s.mem.Remove(id)

	if _, err := s.db.Exec("DELETE FROM grants WHERE id = ?", id); err != nil {
		slog.Error("failed to delete grant from db", "grant_id", id, "error", err)
	}
}

// FindMatch delegates to the in-memory store. One-shot consumption
// also triggers DB deletion and records the used literal.
func (s *SQLiteGrantStore) FindMatch(method, url, domain, path string) *Grant {
	g := s.mem.FindMatch(method, url, domain, path)
	if g != nil && g.OneShot {
		// Record the used literal before deleting
		s.recordUsedLiteral(g)
		// Already consumed from memory by InMemoryGrantStore.FindMatch;
		// also remove from DB
		if _, err := s.db.Exec("DELETE FROM grants WHERE id = ?", g.ID); err != nil {
			slog.Error("failed to delete one-shot grant from db", "grant_id", g.ID, "error", err)
		}
	}
	return g
}

func (s *SQLiteGrantStore) recordUsedLiteral(g *Grant) {
	var expiresAt *time.Time
	if !g.ExpiresAt.IsZero() {
		t := g.ExpiresAt.UTC()
		expiresAt = &t
	}
	durationSec := int64(g.Duration / time.Second)

	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO used_literals
		(id, type, domain, path_prefix, method, url, granted_at, duration_s, expires_at, source, signature, used_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		g.ID, g.Type,
		nullStr(g.Domain), nullStr(g.PathPrefix), nullStr(g.Method), nullStr(g.URL),
		g.GrantedAt.UTC(), durationSec, expiresAt, g.Source, g.Signature,
		time.Now().UTC(),
	)
	if err != nil {
		slog.Error("failed to record used literal", "grant_id", g.ID, "error", err)
	}
}

// UsedLiteral represents a consumed one-shot grant.
type UsedLiteral struct {
	Grant
	UsedAt time.Time `json:"used_at"`
}

// ListUsedLiterals returns all consumed one-shot grants.
func (s *SQLiteGrantStore) ListUsedLiterals() ([]*UsedLiteral, error) {
	rows, err := s.db.Query(`
		SELECT id, type, domain, path_prefix, method, url,
		       granted_at, duration_s, expires_at, source, signature, used_at
		FROM used_literals
		ORDER BY used_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*UsedLiteral
	for rows.Next() {
		var ul UsedLiteral
		var domain, pathPrefix, method, url sql.NullString
		var expiresAt sql.NullTime
		var durationSec int64
		var signature []byte

		if err := rows.Scan(
			&ul.ID, &ul.Type, &domain, &pathPrefix, &method, &url,
			&ul.GrantedAt, &durationSec, &expiresAt, &ul.Source, &signature, &ul.UsedAt,
		); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}

		ul.Domain = domain.String
		ul.PathPrefix = pathPrefix.String
		ul.Method = method.String
		ul.URL = url.String
		ul.Duration = time.Duration(durationSec) * time.Second
		if expiresAt.Valid {
			ul.ExpiresAt = expiresAt.Time
		}
		ul.Signature = signature

		result = append(result, &ul)
	}
	return result, rows.Err()
}

// List delegates to the in-memory store.
func (s *SQLiteGrantStore) List() []*Grant {
	return s.mem.List()
}

// RemoveBySource removes grants by source from memory. If the source is
// not "policy", also removes from DB.
func (s *SQLiteGrantStore) RemoveBySource(source string) {
	s.mem.RemoveBySource(source)

	if source != "policy" {
		if _, err := s.db.Exec("DELETE FROM grants WHERE source = ?", source); err != nil {
			slog.Error("failed to delete grants by source from db", "source", source, "error", err)
		}
	}
}

// Close closes the SQLite database.
func (s *SQLiteGrantStore) Close() error {
	return s.db.Close()
}

// nullStr returns a sql.NullString, NULL if the string is empty.
func nullStr(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

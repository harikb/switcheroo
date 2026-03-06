package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const refreshEarlyBy = 30 * time.Second

// TokenState holds the mutable token state for a single OAuth route.
type TokenState struct {
	mu           sync.Mutex
	routePath    string
	tokenURL     string
	clientID     string
	clientSecret string
	accessToken  string
	refreshToken string
	scopes       []string
	expiresAt    time.Time
	store        *TokenStore
}

// persistedToken is the JSON-serializable form of a token.
type persistedToken struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// GetAccessToken returns a valid access token, refreshing if needed.
func (ts *TokenState) GetAccessToken() (string, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if ts.accessToken != "" && time.Now().Before(ts.expiresAt.Add(-refreshEarlyBy)) {
		return ts.accessToken, nil
	}

	// Need to refresh
	if err := ts.refreshLocked(); err != nil {
		// If refresh fails but we still have a non-expired token, use it
		if ts.accessToken != "" && time.Now().Before(ts.expiresAt) {
			slog.Warn("refresh failed but token still valid", "route", ts.routePath, "error", err)
			return ts.accessToken, nil
		}
		return "", fmt.Errorf("token refresh for %s: %w", ts.routePath, err)
	}

	return ts.accessToken, nil
}

// ForceRefresh forces a token refresh. Returns true if a new token was obtained.
func (ts *TokenState) ForceRefresh() (bool, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	err := ts.refreshLocked()
	return err == nil, err
}

func (ts *TokenState) refreshLocked() error {
	var data url.Values

	if ts.refreshToken != "" {
		// Refresh token grant
		data = url.Values{
			"grant_type":    {"refresh_token"},
			"client_id":     {ts.clientID},
			"client_secret": {ts.clientSecret},
			"refresh_token": {ts.refreshToken},
		}
	} else {
		// Client credentials grant
		data = url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {ts.clientID},
			"client_secret": {ts.clientSecret},
		}
		if len(ts.scopes) > 0 {
			data.Set("scope", strings.Join(ts.scopes, " "))
		}
	}

	slog.Info("refreshing token", "route", ts.routePath, "token_url", ts.tokenURL)

	resp, err := http.PostForm(ts.tokenURL, data)
	if err != nil {
		return fmt.Errorf("POST %s: %w", ts.tokenURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errBody json.RawMessage
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		return fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(errBody))
	}

	var result struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		TokenType    string `json:"token_type"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding token response: %w", err)
	}

	ts.accessToken = result.AccessToken
	if result.RefreshToken != "" {
		ts.refreshToken = result.RefreshToken
	}
	if result.ExpiresIn > 0 {
		ts.expiresAt = time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)
	} else {
		ts.expiresAt = time.Now().Add(1 * time.Hour) // default
	}

	slog.Info("token refreshed", "route", ts.routePath, "expires_at", ts.expiresAt.Format(time.RFC3339))

	ts.store.persist()
	return nil
}

// TokenStore manages token state for all OAuth routes and handles persistence.
type TokenStore struct {
	mu       sync.Mutex
	states   map[string]*TokenState
	filePath string
}

func NewTokenStore(filePath string) *TokenStore {
	return &TokenStore{
		states:   make(map[string]*TokenState),
		filePath: filePath,
	}
}

// Load reads persisted token state from disk.
func (s *TokenStore) Load() error {
	if s.filePath == "" {
		return nil
	}

	data, err := os.ReadFile(s.filePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading token state: %w", err)
	}

	var persisted map[string]persistedToken
	if err := json.Unmarshal(data, &persisted); err != nil {
		return fmt.Errorf("parsing token state file: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for path, pt := range persisted {
		if state, ok := s.states[path]; ok {
			state.mu.Lock()
			if pt.AccessToken != "" {
				state.accessToken = pt.AccessToken
			}
			if pt.RefreshToken != "" {
				state.refreshToken = pt.RefreshToken
			}
			if !pt.ExpiresAt.IsZero() {
				state.expiresAt = pt.ExpiresAt
			}
			state.mu.Unlock()
			slog.Info("loaded persisted token", "route", path, "expires_at", pt.ExpiresAt.Format(time.RFC3339))
		}
	}

	return nil
}

// GetOrCreate returns the TokenState for a route, creating it if needed.
func (s *TokenStore) GetOrCreate(routePath, tokenURL, clientID, clientSecret, accessToken, refreshToken string, scopes []string) *TokenState {
	s.mu.Lock()
	defer s.mu.Unlock()

	if state, ok := s.states[routePath]; ok {
		return state
	}

	state := &TokenState{
		routePath:    routePath,
		tokenURL:     tokenURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		accessToken:  accessToken,
		refreshToken: refreshToken,
		scopes:       scopes,
		store:        s,
	}
	s.states[routePath] = state
	return state
}

// persist writes all token state to disk atomically.
func (s *TokenStore) persist() {
	if s.filePath == "" {
		return
	}

	s.mu.Lock()
	persisted := make(map[string]persistedToken)
	for path, state := range s.states {
		// state.mu is already held by caller in refreshLocked
		persisted[path] = persistedToken{
			AccessToken:  state.accessToken,
			RefreshToken: state.refreshToken,
			ExpiresAt:    state.expiresAt,
		}
	}
	s.mu.Unlock()

	data, err := json.MarshalIndent(persisted, "", "  ")
	if err != nil {
		slog.Error("error marshaling token state", "error", err)
		return
	}

	// Atomic write: write to temp file, then rename
	dir := filepath.Dir(s.filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		slog.Error("error creating token state dir", "error", err)
		return
	}

	tmp := s.filePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		slog.Error("error writing token state", "error", err)
		return
	}
	if err := os.Rename(tmp, s.filePath); err != nil {
		slog.Error("error renaming token state", "error", err)
	}
}

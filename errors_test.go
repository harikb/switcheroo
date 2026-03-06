package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteErrorResponse(t *testing.T) {
	w := httptest.NewRecorder()
	writeErrorResponse(w, http.StatusForbidden, ErrorResponse{
		Error:   "not_allowed",
		Message: "No matching grant found",
		Domain:  "api.stripe.com",
	})

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected application/json, got %s", ct)
	}

	var resp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if resp.Error != "not_allowed" {
		t.Fatalf("expected error=not_allowed, got %s", resp.Error)
	}
	if resp.Message != "No matching grant found" {
		t.Fatalf("expected message, got %s", resp.Message)
	}
	if resp.Domain != "api.stripe.com" {
		t.Fatalf("expected domain, got %s", resp.Domain)
	}
}

func TestOptionalFieldOmission(t *testing.T) {
	w := httptest.NewRecorder()
	writeErrorResponse(w, http.StatusForbidden, ErrorResponse{
		Error:   "denied",
		Message: "Domain is denied",
	})

	var raw map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &raw)

	if _, ok := raw["request_id"]; ok {
		t.Fatal("expected request_id to be omitted when empty")
	}
	if _, ok := raw["domain"]; ok {
		t.Fatal("expected domain to be omitted when empty")
	}
	if _, ok := raw["route"]; ok {
		t.Fatal("expected route to be omitted when empty")
	}
	if _, ok := raw["hint"]; ok {
		t.Fatal("expected hint to be omitted when empty")
	}
}

func TestNotAllowedError(t *testing.T) {
	resp := notAllowedError("GET", "api.stripe.com", "/v1/charges", "/api")
	if resp.Error != "not_allowed" {
		t.Fatalf("expected not_allowed, got %s", resp.Error)
	}
	if resp.Domain != "api.stripe.com" {
		t.Fatalf("expected domain, got %s", resp.Domain)
	}
	if resp.Route != "/api" {
		t.Fatalf("expected route /api, got %s", resp.Route)
	}
	if !strings.Contains(resp.Message, "GET api.stripe.com/v1/charges") {
		t.Fatalf("expected message to contain method and upstream path, got %s", resp.Message)
	}
	if !strings.Contains(resp.Message, "route /api") {
		t.Fatalf("expected message to contain route mapping, got %s", resp.Message)
	}
}

func TestNotAllowedErrorNoRoute(t *testing.T) {
	resp := notAllowedError("GET", "example.com", "/path", "")
	if resp.Route != "" {
		t.Fatalf("expected empty route, got %s", resp.Route)
	}
	if strings.Contains(resp.Message, "route") {
		t.Fatalf("expected no route mapping in message for forward proxy, got %s", resp.Message)
	}
}

func TestDeniedError(t *testing.T) {
	resp := deniedError("POST", "evil.com", "/hack", "/api")
	if resp.Error != "denied" {
		t.Fatalf("expected denied, got %s", resp.Error)
	}
	if resp.Route != "/api" {
		t.Fatalf("expected route /api, got %s", resp.Route)
	}
	if !strings.Contains(resp.Message, "POST evil.com/hack") {
		t.Fatalf("expected message to contain method and path, got %s", resp.Message)
	}
}

func TestDeniedErrorNoRoute(t *testing.T) {
	resp := deniedError("GET", "evil.com", "/hack", "")
	if resp.Route != "" {
		t.Fatalf("expected empty route, got %s", resp.Route)
	}
	if strings.Contains(resp.Message, "Route") {
		t.Fatalf("expected no route mapping in message for forward proxy, got %s", resp.Message)
	}
}

func TestDeclawRequiredError(t *testing.T) {
	resp := declawRequiredError()
	if resp.Error != "declaw_required" {
		t.Fatalf("expected declaw_required, got %s", resp.Error)
	}
	if resp.Hint == "" {
		t.Fatal("expected hint for declaw_required")
	}
	if !strings.Contains(resp.Message, "DeClaw") {
		t.Fatalf("expected DeClaw in message, got %s", resp.Message)
	}
}

func TestExpiredGrantError(t *testing.T) {
	resp := expiredGrantError("api.stripe.com", "/v1/charges")
	if resp.Error != "grant_expired" {
		t.Fatalf("expected grant_expired, got %s", resp.Error)
	}
	if !strings.Contains(resp.Message, "expired") {
		t.Fatalf("expected expired in message, got %s", resp.Message)
	}
}

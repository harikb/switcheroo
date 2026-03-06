package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ErrorResponse is the structured JSON error returned by switcheroo.
type ErrorResponse struct {
	Error     string `json:"error"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
	Domain    string `json:"domain,omitempty"`
	Route     string `json:"route,omitempty"`
	Hint      string `json:"hint,omitempty"`
}

func writeErrorResponse(w http.ResponseWriter, code int, resp ErrorResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(resp)
}

func notAllowedError(method, domain, path, routePrefix string) ErrorResponse {
	msg := fmt.Sprintf("No matching grant covers %s %s%s.", method, domain, path)
	if routePrefix != "" {
		msg += fmt.Sprintf(" The request was received on route %s which maps to %s. To allow this request, add a policy grant or approve it via DeClaw.", routePrefix, domain)
	}
	return ErrorResponse{
		Error:   "not_allowed",
		Message: msg,
		Domain:  domain,
		Route:   routePrefix,
	}
}

func deniedError(method, domain, path, routePrefix string) ErrorResponse {
	msg := fmt.Sprintf("Request denied by policy: %s %s%s is explicitly blocked by a deny rule.", method, domain, path)
	if routePrefix != "" {
		msg += fmt.Sprintf(" Route %s maps to %s.", routePrefix, domain)
	}
	return ErrorResponse{
		Error:   "denied",
		Message: msg,
		Domain:  domain,
		Route:   routePrefix,
	}
}

func declawRequiredError() ErrorResponse {
	return ErrorResponse{
		Error:   "declaw_required",
		Message: "This request requires real-time approval from a paired DeClaw phone. No policy grant covers this domain/path, and no DeClaw device is connected to approve it.",
		Hint:    "Connect a DeClaw-compatible phone to approve this request",
	}
}

func expiredGrantError(domain, path string) ErrorResponse {
	return ErrorResponse{
		Error:   "grant_expired",
		Message: fmt.Sprintf("The grant that previously allowed access to %s%s has expired. Request a new grant via DeClaw or update the policy configuration.", domain, path),
		Domain:  domain,
	}
}

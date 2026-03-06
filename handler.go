package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type routeEntry struct {
	route    Route
	auth     AuthProvider
	upstream *url.URL
}

type ProxyHandler struct {
	routes          []routeEntry // sorted by path length descending
	mode            string
	grantStore      GrantStore
	denyList        *DenyList
	forwardProxy    *ForwardProxyHandler
	mgmtAPI         *ManagementAPI
	declawClient    *GatewayClient
	mgmtAllowedNets []*net.IPNet
}

func parseURL(rawURL string) (*url.URL, error) {
	return url.Parse(rawURL)
}

func NewProxyHandler(cfg *Config, store *TokenStore) (*ProxyHandler, error) {
	h := &ProxyHandler{
		mode: cfg.Server.Mode,
	}

	for _, route := range cfg.Routes {
		u, err := url.Parse(route.Upstream)
		if err != nil {
			return nil, err
		}
		auth := NewAuthProvider(route, store)
		h.routes = append(h.routes, routeEntry{
			route:    route,
			auth:     auth,
			upstream: u,
		})
	}

	return h, nil
}

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Management API routing
	if strings.HasPrefix(r.URL.Path, "/_switcheroo/") && h.mgmtAPI != nil {
		if !h.isAllowedManagementAccess(r.RemoteAddr) {
			writeErrorResponse(w, http.StatusForbidden, ErrorResponse{
				Error:   "forbidden",
				Message: "Management API is only accessible from loopback or allowed CIDRs",
			})
			return
		}
		h.mgmtAPI.ServeHTTP(w, r)
		return
	}

	// Forward proxy detection
	if h.forwardProxy != nil && h.forwardProxy.IsForwardProxyRequest(r) {
		h.forwardProxy.ServeHTTP(w, r)
		return
	}

	// Match route by longest prefix
	var matched *routeEntry
	for i := range h.routes {
		prefix := h.routes[i].route.Path
		if r.URL.Path == prefix || strings.HasPrefix(r.URL.Path, prefix+"/") {
			matched = &h.routes[i]
			break
		}
	}

	if matched == nil {
		var prefixes []string
		for _, e := range h.routes {
			prefixes = append(prefixes, e.route.Path)
		}
		hint := ""
		if len(prefixes) > 0 {
			hint = "Available route prefixes: " + strings.Join(prefixes, ", ")
		}
		writeErrorResponse(w, http.StatusNotFound, ErrorResponse{
			Error:   "no_route",
			Message: fmt.Sprintf("No route is configured that matches the path '%s'. Check your switcheroo config for available route prefixes.", r.URL.Path),
			Hint:    hint,
		})
		return
	}

	route := matched.route

	// Inbound auth check
	if route.InboundAuth != nil {
		got := r.Header.Get(route.InboundAuth.Header)
		if got != route.InboundAuth.Value {
			slog.Warn("inbound auth failed", "route", route.Path, "remote_addr", r.RemoteAddr)
			writeErrorResponse(w, http.StatusUnauthorized, ErrorResponse{
				Error:   "unauthorized",
				Message: "Inbound authentication failed: the required header did not match. This route requires a valid inbound auth header.",
			})
			return
		}
	}

	// Grant gating check (after inbound auth, before upstream)
	if h.mode == "gated" {
		domain := extractDomainFromUpstream(matched.upstream)
		upstreamPath := strings.TrimPrefix(r.URL.Path, route.Path)
		if upstreamPath == "" {
			upstreamPath = "/"
		}

		approvalMode := route.Approval
		if approvalMode == "" {
			approvalMode = "required"
		}

		// "auto" mode: skip all gating
		if approvalMode == "auto" {
			// pass through to upstream
		} else if approvalMode == "notify-only" {
			// Send informational notification, don't block
			if h.declawClient != nil {
				go h.declawClient.SendNotifyOnly(RequestMetadata{
					RequestID: generateRequestID(),
					ProxyID:   h.declawClient.proxyID,
					Domain:    domain,
					Method:    r.Method,
					URL:       r.URL.String(),
				})
			}
		} else {
			// "required" mode: full grant check

			// Check deny list first
			if denied, _ := h.denyList.IsDeniedMethod(domain, upstreamPath, r.Method); denied {
				writeErrorResponse(w, http.StatusForbidden, deniedError(r.Method, domain, upstreamPath, route.Path))
				return
			}

			// Check grant store
			grant := h.grantStore.FindMatch(r.Method, "", domain, upstreamPath)
			if grant == nil && h.declawClient != nil {
				// Determine timeout
				timeout := h.declawClient.approvalTimeout
				if route.ApprovalTimeout != "" {
					if d, err := time.ParseDuration(route.ApprovalTimeout); err == nil {
						timeout = d
					}
				}
				result, err := h.declawClient.RequestApprovalWithTimeout(r.Context(), RequestMetadata{
					RequestID: generateRequestID(),
					ProxyID:   h.declawClient.proxyID,
					Domain:    domain,
					Method:    r.Method,
					URL:       r.URL.String(),
				}, timeout)
				if err != nil || !result.Approved {
					if h.mgmtAPI != nil {
						reason := "declaw_denied"
						if err != nil {
							reason = "declaw_timeout"
						}
						h.mgmtAPI.RecordDenied(DeniedRequest{
							Timestamp: time.Now(),
							Method:    r.Method,
							Domain:    domain,
							Path:      upstreamPath,
							Reason:    reason,
						})
					}
					writeErrorResponse(w, http.StatusForbidden, notAllowedError(r.Method, domain, upstreamPath, route.Path))
					return
				}
				if result.Grant != nil {
					h.grantStore.Add(result.Grant)
				}
			} else if grant == nil {
				writeErrorResponse(w, http.StatusForbidden, notAllowedError(r.Method, domain, upstreamPath, route.Path))
				return
			}
		}
	}

	// Build upstream request
	upstreamHost := matched.upstream.Host
	resp, err := h.doUpstreamRequest(r, matched, false)
	if err != nil {
		slog.Error("upstream error", "route", route.Path, "error", err)
		writeErrorResponse(w, http.StatusBadGateway, ErrorResponse{
			Error:   "upstream_error",
			Message: fmt.Sprintf("The upstream server at %s failed to respond for route '%s'", upstreamHost, route.Path),
		})
		return
	}

	// If 401 from upstream and auth supports refresh, retry once
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		if refreshed, err := matched.auth.ForceRefresh(); refreshed && err == nil {
			slog.Info("retrying after token refresh", "route", route.Path)
			resp, err = h.doUpstreamRequest(r, matched, true)
			if err != nil {
				slog.Error("upstream error on retry", "route", route.Path, "error", err)
				writeErrorResponse(w, http.StatusBadGateway, ErrorResponse{
					Error:   "upstream_error",
					Message: fmt.Sprintf("The upstream server at %s failed to respond for route '%s'", upstreamHost, route.Path),
				})
				return
			}
		}
	}
	defer resp.Body.Close()

	// Copy response headers and body
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (h *ProxyHandler) doUpstreamRequest(r *http.Request, entry *routeEntry, isRetry bool) (*http.Response, error) {
	route := entry.route

	// Strip path prefix
	strippedPath := strings.TrimPrefix(r.URL.Path, route.Path)
	if strippedPath == "" {
		strippedPath = "/"
	}

	// Build upstream URL
	upstreamURL := *entry.upstream
	upstreamURL.Path = upstreamURL.Path + strippedPath
	upstreamURL.RawQuery = r.URL.RawQuery

	// Create new request (can't reuse body on retry for non-GET, but for the
	// common case of 401 retry the body was likely not consumed)
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL.String(), r.Body)
	if err != nil {
		return nil, err
	}

	// Copy headers from original request
	for k, vv := range r.Header {
		for _, v := range vv {
			outReq.Header.Add(k, v)
		}
	}

	// Strip inbound auth header before forwarding
	if route.InboundAuth != nil && route.InboundAuth.Strip {
		outReq.Header.Del(route.InboundAuth.Header)
	}

	// Set Host header to upstream host
	outReq.Host = entry.upstream.Host

	// Apply upstream auth
	if err := entry.auth.ApplyAuth(outReq); err != nil {
		return nil, err
	}

	// Add extra headers
	for k, v := range route.ExtraHeaders {
		outReq.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := http.DefaultTransport.RoundTrip(outReq)
	if err != nil {
		return nil, err
	}

	slog.Info("proxy request",
		"route", route.Path, "method", r.Method, "url", r.URL.Path,
		"upstream", upstreamURL.String(), "status_code", resp.StatusCode,
		"latency", time.Since(start).Round(time.Millisecond).String())

	return resp, nil
}

// extractDomainFromUpstream extracts the hostname from an upstream URL.
func extractDomainFromUpstream(u *url.URL) string {
	host := u.Hostname()
	if host == "" {
		return u.Host
	}
	return host
}

// generateRequestID generates a random hex request ID.
func generateRequestID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// parseCIDRs parses a list of CIDR strings into []*net.IPNet.
// Returns an error if any CIDR is invalid.
func parseCIDRs(cidrs []string) ([]*net.IPNet, error) {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		nets = append(nets, ipNet)
	}
	return nets, nil
}

// isAllowedManagementAccess checks if the remote address is allowed to access the management API.
// Loopback is always allowed. Configured CIDRs are also allowed.
func (h *ProxyHandler) isAllowedManagementAccess(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return host == "localhost"
	}
	if ip.IsLoopback() {
		return true
	}
	for _, n := range h.mgmtAllowedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// isLoopback checks if the remote address is a loopback address.
func isLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip != nil {
		return ip.IsLoopback()
	}
	return host == "localhost"
}

package main

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

// ForwardProxyHandler handles HTTP CONNECT tunneling and absolute URI proxying.
type ForwardProxyHandler struct {
	enabled      bool
	allowedPorts map[int]bool
	bypass       map[string]bool
	grantStore   GrantStore
	denyList     *DenyList
	declawClient *GatewayClient
	mgmtAPI      *ManagementAPI
}

func NewForwardProxyHandler(cfg ForwardProxyConfig, grantStore GrantStore, denyList *DenyList) *ForwardProxyHandler {
	ports := make(map[int]bool)
	for _, p := range cfg.AllowedPorts {
		ports[p] = true
	}

	byp := make(map[string]bool)
	for _, b := range cfg.Bypass {
		byp[strings.ToLower(b)] = true
	}

	return &ForwardProxyHandler{
		enabled:      cfg.Enabled,
		allowedPorts: ports,
		bypass:       byp,
		grantStore:   grantStore,
		denyList:     denyList,
	}
}

// IsForwardProxyRequest detects if a request is a forward proxy request.
// CONNECT method or absolute URI in the request line indicates forward proxy.
func (fp *ForwardProxyHandler) IsForwardProxyRequest(r *http.Request) bool {
	if !fp.enabled {
		return false
	}
	if r.Method == http.MethodConnect {
		return true
	}
	// Absolute URI: scheme present in request URL
	if r.URL.IsAbs() {
		return true
	}
	return false
}

func (fp *ForwardProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !fp.enabled {
		writeErrorResponse(w, http.StatusForbidden, ErrorResponse{
			Error:   "forward_proxy_disabled",
			Message: "Forward proxy is not enabled",
		})
		return
	}

	if r.Method == http.MethodConnect {
		fp.handleConnect(w, r)
		return
	}

	// Absolute URI proxy
	fp.handleAbsoluteURI(w, r)
}

func (fp *ForwardProxyHandler) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, portStr, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
		portStr = "443"
	}

	port := 443
	if portStr != "" {
		fmt.Sscanf(portStr, "%d", &port)
	}

	// Port filtering
	if !fp.allowedPorts[port] {
		writeErrorResponse(w, http.StatusForbidden, ErrorResponse{
			Error:   "port_not_allowed",
			Message: fmt.Sprintf("Port %d is not in the allowed ports list", port),
		})
		return
	}

	// Bypass check
	if !fp.isBypassed(host) {
		// Deny check
		if denied, _ := fp.denyList.IsDenied(host, "/"); denied {
			writeErrorResponse(w, http.StatusForbidden, deniedError("CONNECT", host, "/", ""))
			return
		}

		// Grant check
		grant := fp.grantStore.FindMatch("CONNECT", "", host, "/")
		if grant == nil && fp.declawClient != nil {
			result, err := fp.declawClient.RequestApproval(r.Context(), RequestMetadata{
				RequestID: generateRequestID(),
				ProxyID:   fp.declawClient.proxyID,
				Domain:    host,
				Method:    "CONNECT",
			})
			if err != nil || !result.Approved {
				if fp.mgmtAPI != nil {
					reason := "declaw_denied"
					if err != nil {
						reason = "declaw_timeout"
					}
					fp.mgmtAPI.RecordDenied(DeniedRequest{
						Timestamp: time.Now(),
						Method:    "CONNECT",
						Domain:    host,
						Path:      "/",
						Reason:    reason,
					})
				}
				writeErrorResponse(w, http.StatusForbidden, notAllowedError("CONNECT", host, "/", ""))
				return
			}
			if result.Grant != nil {
				fp.grantStore.Add(result.Grant)
			}
		} else if grant == nil {
			writeErrorResponse(w, http.StatusForbidden, notAllowedError("CONNECT", host, "/", ""))
			return
		}
	}

	// Establish tunnel
	destConn, err := net.DialTimeout("tcp", net.JoinHostPort(host, portStr), 10*time.Second)
	if err != nil {
		writeErrorResponse(w, http.StatusBadGateway, ErrorResponse{
			Error:   "connect_error",
			Message: fmt.Sprintf("Could not establish a connection to %s:%s: %v", host, portStr, err),
			Domain:  host,
		})
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		destConn.Close()
		writeErrorResponse(w, http.StatusInternalServerError, ErrorResponse{
			Error:   "internal_error",
			Message: "CONNECT tunnel failed: the HTTP server does not support connection hijacking. This is a switcheroo server configuration issue.",
		})
		return
	}

	// Send 200 Connection Established
	clientConn, buf, err := hijacker.Hijack()
	if err != nil {
		destConn.Close()
		writeErrorResponse(w, http.StatusInternalServerError, ErrorResponse{
			Error:   "internal_error",
			Message: fmt.Sprintf("CONNECT tunnel failed: connection hijack error: %v", err),
		})
		return
	}

	fmt.Fprintf(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")

	// Bidirectional copy
	go func() {
		defer destConn.Close()
		defer clientConn.Close()
		io.Copy(destConn, buf)
	}()
	go func() {
		defer destConn.Close()
		defer clientConn.Close()
		io.Copy(clientConn, destConn)
	}()

	slog.Info("forward proxy CONNECT", "host", r.Host)
}

func (fp *ForwardProxyHandler) handleAbsoluteURI(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Hostname()
	path := r.URL.Path

	// Bypass check
	if !fp.isBypassed(host) {
		// Deny check
		if denied, _ := fp.denyList.IsDeniedMethod(host, path, r.Method); denied {
			writeErrorResponse(w, http.StatusForbidden, deniedError(r.Method, host, path, ""))
			return
		}

		// Grant check
		grant := fp.grantStore.FindMatch(r.Method, r.URL.String(), host, path)
		if grant == nil && fp.declawClient != nil {
			result, err := fp.declawClient.RequestApproval(r.Context(), RequestMetadata{
				RequestID: generateRequestID(),
				ProxyID:   fp.declawClient.proxyID,
				Domain:    host,
				Method:    r.Method,
				URL:       r.URL.String(),
			})
			if err != nil || !result.Approved {
				if fp.mgmtAPI != nil {
					reason := "declaw_denied"
					if err != nil {
						reason = "declaw_timeout"
					}
					fp.mgmtAPI.RecordDenied(DeniedRequest{
						Timestamp: time.Now(),
						Method:    r.Method,
						Domain:    host,
						Path:      path,
						Reason:    reason,
					})
				}
				writeErrorResponse(w, http.StatusForbidden, notAllowedError(r.Method, host, path, ""))
				return
			}
			if result.Grant != nil {
				fp.grantStore.Add(result.Grant)
			}
		} else if grant == nil {
			writeErrorResponse(w, http.StatusForbidden, notAllowedError(r.Method, host, path, ""))
			return
		}
	}

	// Forward the request
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
	if err != nil {
		writeErrorResponse(w, http.StatusBadRequest, ErrorResponse{
			Error:   "bad_request",
			Message: "Could not construct a valid upstream request from the forwarded request",
		})
		return
	}
	for k, vv := range r.Header {
		for _, v := range vv {
			outReq.Header.Add(k, v)
		}
	}
	outReq.Header.Del("Proxy-Connection")

	resp, err := http.DefaultTransport.RoundTrip(outReq)
	if err != nil {
		writeErrorResponse(w, http.StatusBadGateway, ErrorResponse{
			Error:   "upstream_error",
			Message: fmt.Sprintf("The upstream server failed to respond: %v", err),
			Domain:  host,
		})
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)

	slog.Info("forward proxy request", "method", r.Method, "url", r.URL.String(), "status_code", resp.StatusCode)
}

func (fp *ForwardProxyHandler) isBypassed(host string) bool {
	return fp.bypass[strings.ToLower(host)]
}

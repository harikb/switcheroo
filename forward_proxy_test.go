package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestForwardProxyDisabled(t *testing.T) {
	store := NewInMemoryGrantStore()
	deny := NewDenyList(nil)
	fp := NewForwardProxyHandler(ForwardProxyConfig{Enabled: false}, store, deny)

	req := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
	w := httptest.NewRecorder()
	fp.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestForwardProxyDetection(t *testing.T) {
	store := NewInMemoryGrantStore()
	deny := NewDenyList(nil)
	fp := NewForwardProxyHandler(ForwardProxyConfig{Enabled: true, AllowedPorts: []int{80, 443}}, store, deny)

	// CONNECT = forward proxy
	req := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
	if !fp.IsForwardProxyRequest(req) {
		t.Fatal("expected CONNECT to be detected as forward proxy")
	}

	// Absolute URI = forward proxy
	req = httptest.NewRequest("GET", "http://example.com/path", nil)
	if !fp.IsForwardProxyRequest(req) {
		t.Fatal("expected absolute URI to be detected as forward proxy")
	}

	// Relative path = reverse proxy
	req = httptest.NewRequest("GET", "/api/test", nil)
	if fp.IsForwardProxyRequest(req) {
		t.Fatal("expected relative path to NOT be forward proxy")
	}
}

func TestForwardProxyDetectionDisabled(t *testing.T) {
	store := NewInMemoryGrantStore()
	deny := NewDenyList(nil)
	fp := NewForwardProxyHandler(ForwardProxyConfig{Enabled: false}, store, deny)

	req := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
	if fp.IsForwardProxyRequest(req) {
		t.Fatal("disabled proxy should not detect forward proxy requests")
	}
}

func TestCONNECTAllowedWithGrant(t *testing.T) {
	// Create a real TCP listener to act as the destination
	destListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer destListener.Close()
	_, destPort, _ := net.SplitHostPort(destListener.Addr().String())

	// Get the port as int for allowed ports config
	var destPortInt int
	fmt.Sscanf(destPort, "%d", &destPortInt)

	store := NewInMemoryGrantStore()
	store.Add(&Grant{
		ID:     "connect-grant",
		Type:   GrantTypeDomain,
		Domain: "127.0.0.1",
		Source: "policy",
	})
	deny := NewDenyList(nil)
	fp := NewForwardProxyHandler(ForwardProxyConfig{
		Enabled:      true,
		AllowedPorts: []int{destPortInt},
	}, store, deny)

	// Accept connections in background and send test data
	go func() {
		conn, err := destListener.Accept()
		if err != nil {
			return
		}
		conn.Write([]byte("hello from tunnel"))
		conn.Close()
	}()

	// Use a real HTTP server with the forward proxy handler
	server := httptest.NewServer(fp)
	defer server.Close()

	// Simulate a CONNECT via raw TCP
	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT 127.0.0.1:%s HTTP/1.1\r\nHost: 127.0.0.1:%s\r\n\r\n", destPort, destPort)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("error reading response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Read tunneled data
	buf := make([]byte, 100)
	n, _ := br.Read(buf)
	if string(buf[:n]) != "hello from tunnel" {
		t.Fatalf("expected tunnel data, got %q", string(buf[:n]))
	}
}

func TestCONNECTDeniedNoGrant(t *testing.T) {
	store := NewInMemoryGrantStore() // empty
	deny := NewDenyList(nil)
	fp := NewForwardProxyHandler(ForwardProxyConfig{
		Enabled:      true,
		AllowedPorts: []int{80, 443},
	}, store, deny)

	req := httptest.NewRequest(http.MethodConnect, "unknown.com:443", nil)
	req.Host = "unknown.com:443"
	w := httptest.NewRecorder()
	fp.handleConnect(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	var errResp ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error != "not_allowed" {
		t.Fatalf("expected not_allowed, got %s", errResp.Error)
	}
}

func TestCONNECTDenyRule(t *testing.T) {
	store := NewInMemoryGrantStore()
	store.Add(&Grant{
		ID:     "allow",
		Type:   GrantTypeDomain,
		Domain: "evil.com",
		Source: "policy",
	})
	deny := NewDenyList([]PolicyRule{
		{Domain: "evil.com"},
	})
	fp := NewForwardProxyHandler(ForwardProxyConfig{
		Enabled:      true,
		AllowedPorts: []int{443},
	}, store, deny)

	req := httptest.NewRequest(http.MethodConnect, "evil.com:443", nil)
	req.Host = "evil.com:443"
	w := httptest.NewRecorder()
	fp.handleConnect(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	var errResp ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error != "denied" {
		t.Fatalf("expected denied, got %s", errResp.Error)
	}
}

func TestCONNECTPortFiltering(t *testing.T) {
	store := NewInMemoryGrantStore()
	store.Add(&Grant{
		ID:     "grant",
		Type:   GrantTypeDomain,
		Domain: "example.com",
		Source: "policy",
	})
	deny := NewDenyList(nil)
	fp := NewForwardProxyHandler(ForwardProxyConfig{
		Enabled:      true,
		AllowedPorts: []int{80, 443},
	}, store, deny)

	// Allowed port
	req := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
	req.Host = "example.com:443"
	w := httptest.NewRecorder()
	fp.handleConnect(w, req)
	// Will fail to actually connect, but won't return port_not_allowed
	if w.Code == http.StatusForbidden {
		var errResp ErrorResponse
		json.Unmarshal(w.Body.Bytes(), &errResp)
		if errResp.Error == "port_not_allowed" {
			t.Fatal("port 443 should be allowed")
		}
	}

	// Disallowed port
	req = httptest.NewRequest(http.MethodConnect, "example.com:8080", nil)
	req.Host = "example.com:8080"
	w = httptest.NewRecorder()
	fp.handleConnect(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for port 8080, got %d", w.Code)
	}
	var errResp ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error != "port_not_allowed" {
		t.Fatalf("expected port_not_allowed, got %s", errResp.Error)
	}
}

func TestBypassList(t *testing.T) {
	store := NewInMemoryGrantStore() // no grants
	deny := NewDenyList(nil)
	fp := NewForwardProxyHandler(ForwardProxyConfig{
		Enabled:      true,
		AllowedPorts: []int{80, 443},
		Bypass:       []string{"localhost"},
	}, store, deny)

	// localhost should bypass grant check — won't fail with not_allowed
	req := httptest.NewRequest(http.MethodConnect, "localhost:443", nil)
	req.Host = "localhost:443"
	w := httptest.NewRecorder()
	fp.handleConnect(w, req)

	// It will try to connect and fail (no server listening), but should NOT return 403 not_allowed
	if w.Code == http.StatusForbidden {
		var errResp ErrorResponse
		json.Unmarshal(w.Body.Bytes(), &errResp)
		if errResp.Error == "not_allowed" {
			t.Fatal("localhost should bypass grant check")
		}
	}
}

func TestAbsoluteURIAllowed(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("proxied"))
	}))
	defer upstream.Close()

	store := NewInMemoryGrantStore()
	store.Add(&Grant{
		ID:     "abs-grant",
		Type:   GrantTypeDomain,
		Domain: "127.0.0.1",
		Source: "policy",
	})
	deny := NewDenyList(nil)
	fp := NewForwardProxyHandler(ForwardProxyConfig{
		Enabled:      true,
		AllowedPorts: []int{80, 443},
	}, store, deny)

	req := httptest.NewRequest("GET", upstream.URL+"/get", nil)
	w := httptest.NewRecorder()
	fp.handleAbsoluteURI(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != "proxied" {
		t.Fatalf("expected proxied, got %s", w.Body.String())
	}
}

func TestAbsoluteURIDenied(t *testing.T) {
	store := NewInMemoryGrantStore() // no grants
	deny := NewDenyList(nil)
	fp := NewForwardProxyHandler(ForwardProxyConfig{
		Enabled:      true,
		AllowedPorts: []int{80, 443},
	}, store, deny)

	req := httptest.NewRequest("GET", "http://unknown.com/get", nil)
	w := httptest.NewRecorder()
	fp.handleAbsoluteURI(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestForwardProxyDeclawApprovalAbsoluteURI(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("fp-declaw-ok"))
	}))
	defer upstream.Close()

	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(NotifyResponse{APNSID: "apns-fp"})
	}))
	defer gateway.Close()

	store := NewInMemoryGrantStore()
	deny := NewDenyList(nil)
	pendingStore := NewPendingRequestStore()

	_, phonePub, _ := GenerateX25519KeyPair()
	declawClient := &GatewayClient{
		gatewayURL:         gateway.URL,
		apiKey:             "dk_test",
		httpClient:         &http.Client{Timeout: 5 * time.Second},
		pendingStore:       pendingStore,
		phoneEncryptionKey: phonePub,
		approvalTimeout:    2 * time.Second,
	}

	fp := NewForwardProxyHandler(ForwardProxyConfig{
		Enabled:      true,
		AllowedPorts: []int{80, 443},
	}, store, deny)
	fp.declawClient = declawClient

	go func() {
		time.Sleep(50 * time.Millisecond)
		for i := 0; i < 20; i++ {
			pendingStore.mu.Lock()
			for id := range pendingStore.requests {
				pendingStore.mu.Unlock()
				pendingStore.Resolve(id, ApprovalResult{
					Approved: true,
					Grant: &Grant{
						ID:     "declaw-fp",
						Type:   GrantTypeDomain,
						Domain: "127.0.0.1",
						Source: "declaw",
					},
				})
				return
			}
			pendingStore.mu.Unlock()
			time.Sleep(10 * time.Millisecond)
		}
	}()

	req := httptest.NewRequest("GET", upstream.URL+"/path", nil)
	w := httptest.NewRecorder()
	fp.handleAbsoluteURI(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestForwardProxyDeclawTimeout(t *testing.T) {
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(NotifyResponse{APNSID: "apns-fp"})
	}))
	defer gateway.Close()

	store := NewInMemoryGrantStore()
	deny := NewDenyList(nil)
	pendingStore := NewPendingRequestStore()

	_, phonePub, _ := GenerateX25519KeyPair()
	declawClient := &GatewayClient{
		gatewayURL:         gateway.URL,
		apiKey:             "dk_test",
		httpClient:         &http.Client{Timeout: 5 * time.Second},
		pendingStore:       pendingStore,
		phoneEncryptionKey: phonePub,
		approvalTimeout:    100 * time.Millisecond,
	}

	fp := NewForwardProxyHandler(ForwardProxyConfig{
		Enabled:      true,
		AllowedPorts: []int{80, 443},
	}, store, deny)
	fp.declawClient = declawClient

	req := httptest.NewRequest("GET", "http://unknown.com/path", nil)
	w := httptest.NewRecorder()
	fp.handleAbsoluteURI(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on timeout, got %d", w.Code)
	}
}

func TestForwardProxyDeclawNilStandalone(t *testing.T) {
	store := NewInMemoryGrantStore()
	deny := NewDenyList(nil)
	fp := NewForwardProxyHandler(ForwardProxyConfig{
		Enabled:      true,
		AllowedPorts: []int{80, 443},
	}, store, deny)
	// declawClient is nil — standalone mode

	req := httptest.NewRequest("GET", "http://unknown.com/path", nil)
	w := httptest.NewRecorder()
	fp.handleAbsoluteURI(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 in standalone, got %d", w.Code)
	}
}

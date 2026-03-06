package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"nhooyr.io/websocket"
)

// GatewayClient communicates with the DeClaw gateway via HTTP and WebSocket.
type GatewayClient struct {
	gatewayURL         string
	proxyID            string
	apiKey             string
	httpClient         *http.Client
	pendingStore       *PendingRequestStore
	proxyPrivKey       *ecdh.PrivateKey
	phoneEncryptionKey *ecdh.PublicKey
	phoneSigningKey    *ecdsa.PublicKey
	approvalTimeout    time.Duration
	wsConn             *websocket.Conn
	onApproval         func(requestID string, approval DecryptedApproval)
	onPairResponse     func(payload WSPairPayload)
	onWSConnected      func()
}

// NewGatewayClient creates a new GatewayClient.
func NewGatewayClient(cfg DeclawConfig, pendingStore *PendingRequestStore) *GatewayClient {
	timeout := 60 * time.Second
	return &GatewayClient{
		gatewayURL:      cfg.GatewayURL,
		proxyID:         cfg.ProxyID,
		apiKey:          cfg.ProxyAPIKey,
		httpClient:      &http.Client{Timeout: 30 * time.Second},
		pendingStore:    pendingStore,
		approvalTimeout: timeout,
	}
}

// RegisterResponse is the response from POST /api/v1/proxy/register.
type RegisterResponse struct {
	ProxyID string `json:"proxy_id"`
	APIKey  string `json:"api_key"`
}

// Register registers this proxy with the DeClaw gateway.
func (c *GatewayClient) Register(name string) (string, string, error) {
	body, _ := json.Marshal(map[string]string{"name": name})
	req, err := http.NewRequest("POST", c.gatewayURL+"/api/v1/proxy/register", bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("register: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("register: status %d: %s", resp.StatusCode, respBody)
	}

	var result RegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", fmt.Errorf("register: decode response: %w", err)
	}

	return result.ProxyID, result.APIKey, nil
}

// SetPairingToken sends a bcrypt-hashed pairing token to the gateway.
func (c *GatewayClient) SetPairingToken(tokenHash string, expiresAt time.Time, pairingCode string, proxyPubKey []byte) error {
	body, _ := json.Marshal(map[string]string{
		"pairing_token_hash": tokenHash,
		"expires_at":         expiresAt.Format(time.RFC3339),
		"pairing_code":       pairingCode,
		"proxy_public_key":   base64.StdEncoding.EncodeToString(proxyPubKey),
	})

	req, err := http.NewRequest("POST", c.gatewayURL+"/api/v1/proxy/pairing_token", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("set pairing token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("set pairing token: status %d: %s", resp.StatusCode, respBody)
	}

	return nil
}

// NotifyResponse is the response from POST /api/v1/notify.
type NotifyResponse struct {
	APNSID string `json:"apns_id"`
}

// Notify sends an encrypted notification to the phone via the gateway.
// The gateway resolves the device token from the proxy's identity (Authorization header).
func (c *GatewayClient) Notify(encrypted EncryptedPayload) (string, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"payload": encrypted,
	})

	req, err := http.NewRequest("POST", c.gatewayURL+"/api/v1/notify", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("notify: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("notify: status %d: %s", resp.StatusCode, respBody)
	}

	var result NotifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("notify: decode response: %w", err)
	}

	return result.APNSID, nil
}

// WSMessage is a message received over the WebSocket connection.
type WSMessage struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

// WSApprovalPayload is the payload for an approval_response WebSocket message.
type WSApprovalPayload struct {
	RequestID string           `json:"request_id"`
	Response  ApprovalResponse `json:"response"`
}

// WSPairPayload is the payload for a pair_response WebSocket message.
// Field names match the gateway's PairRelayData JSON serialization.
type WSPairPayload struct {
	PhoneSigningKey    string `json:"signing_public_key"`
	PhoneEncryptionKey string `json:"encryption_public_key"`
}

// ConnectWebSocket establishes a WebSocket connection to the gateway with reconnection.
// After 3 consecutive connection failures, it falls back to HTTP polling until
// the WebSocket reconnects.
func (c *GatewayClient) ConnectWebSocket(ctx context.Context) error {
	backoff := time.Second
	maxBackoff := 30 * time.Second
	consecutiveFailures := 0
	var pollCancel context.CancelFunc

	// When the WS connection succeeds, reset failures and stop polling
	c.onWSConnected = func() {
		consecutiveFailures = 0
		backoff = time.Second
		if pollCancel != nil {
			slog.Info("websocket reconnected, stopping HTTP polling fallback")
			pollCancel()
			pollCancel = nil
		}
	}

	for {
		err := c.connectAndListen(ctx)
		if ctx.Err() != nil {
			if pollCancel != nil {
				pollCancel()
			}
			return ctx.Err()
		}

		consecutiveFailures++
		slog.Warn("declaw websocket disconnected", "error", err, "reconnect_in", backoff, "consecutive_failures", consecutiveFailures)

		// Start polling fallback after 3 consecutive failures
		if consecutiveFailures >= 3 && pollCancel == nil {
			slog.Warn("websocket unavailable, falling back to HTTP polling")
			var pollCtx context.Context
			pollCtx, pollCancel = context.WithCancel(ctx)
			go c.PollForApprovals(pollCtx)
		}

		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			if pollCancel != nil {
				pollCancel()
			}
			return ctx.Err()
		}

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// connectAndListen dials the WebSocket and processes messages.
// It calls onConnected (if set) when the connection is established,
// before entering the read loop.
func (c *GatewayClient) connectAndListen(ctx context.Context) error {
	wsURL := c.gatewayURL + "/api/v1/ws?proxy_id=" + c.proxyID
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+c.apiKey)

	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: headers,
	})
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	c.wsConn = conn
	defer conn.Close(websocket.StatusNormalClosure, "")

	slog.Info("declaw websocket connected", "gateway_url", c.gatewayURL)

	// Signal successful connection
	if c.onWSConnected != nil {
		c.onWSConnected()
	}

	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		c.handleWSMessage(data)
	}
}

func (c *GatewayClient) handleWSMessage(data []byte) {
	var msg WSMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		slog.Error("declaw invalid ws message", "error", err)
		return
	}

	switch msg.Type {
	case "approval_response":
		c.handleApprovalResponse(msg.Payload)
	case "pair_response":
		if c.onPairResponse != nil {
			var payload WSPairPayload
			if err := json.Unmarshal(msg.Payload, &payload); err != nil {
				slog.Error("declaw invalid pair_response", "error", err)
				return
			}
			c.onPairResponse(payload)
		}
	default:
		slog.Warn("declaw unknown ws message type", "type", msg.Type)
	}
}

func (c *GatewayClient) handleApprovalResponse(payload json.RawMessage) {
	var ap WSApprovalPayload
	if err := json.Unmarshal(payload, &ap); err != nil {
		slog.Error("declaw invalid approval payload", "error", err)
		return
	}

	if c.proxyPrivKey == nil || c.phoneSigningKey == nil {
		slog.Error("declaw received approval but crypto keys not configured")
		c.pendingStore.Resolve(ap.RequestID, ApprovalResult{
			Approved: false,
			Error:    fmt.Errorf("crypto keys not configured"),
		})
		return
	}

	// Decrypt
	signed, err := DecryptApproval(ap.Response, c.proxyPrivKey)
	if err != nil {
		slog.Error("declaw decrypt approval failed", "error", err)
		c.pendingStore.Resolve(ap.RequestID, ApprovalResult{
			Approved: false,
			Error:    fmt.Errorf("decrypt: %w", err),
		})
		return
	}

	// Verify signature
	approval, err := VerifyApprovalSignature(signed, c.phoneSigningKey)
	if err != nil {
		slog.Error("declaw verify signature failed", "error", err)
		c.pendingStore.Resolve(ap.RequestID, ApprovalResult{
			Approved: false,
			Error:    fmt.Errorf("verify: %w", err),
		})
		return
	}

	// Replay protection: reject if timestamp is too old
	if approval.Timestamp != "" {
		ts, err := time.Parse(time.RFC3339, approval.Timestamp)
		if err != nil {
			slog.Error("declaw: invalid approval timestamp", "timestamp", approval.Timestamp, "error", err)
			c.pendingStore.Resolve(ap.RequestID, ApprovalResult{
				Approved: false,
				Error:    fmt.Errorf("invalid approval timestamp: %w", err),
			})
			return
		}
		if time.Since(ts) > 5*time.Minute {
			slog.Warn("declaw: approval timestamp too old", "timestamp", approval.Timestamp, "age", time.Since(ts))
			c.pendingStore.Resolve(ap.RequestID, ApprovalResult{
				Approved: false,
				Error:    fmt.Errorf("approval timestamp too old: %v", time.Since(ts)),
			})
			return
		}
	}

	if c.onApproval != nil {
		c.onApproval(approval.RequestID, approval)
	}

	approved := approval.Action == "approve"
	var grant *Grant
	if approved {
		now := time.Now().Add(-10 * time.Second)
		grant = &Grant{
			ID:        "declaw-" + approval.RequestID,
			Domain:    approval.Domain,
			Source:    "declaw",
			GrantedAt: now,
			Signature: signed.Signature,
		}
		switch approval.LeaseType {
		case "literal":
			grant.Type = GrantTypeLiteral
		case "path_prefix":
			grant.Type = GrantTypePathPrefix
			grant.PathPrefix = approval.PathPrefix
		default:
			grant.Type = GrantTypeDomain
		}
		if approval.DurationSeconds > 0 {
			dur := time.Duration(approval.DurationSeconds) * time.Second
			grant.Duration = dur
			grant.ExpiresAt = now.Add(dur)
		}
	}

	c.pendingStore.Resolve(approval.RequestID, ApprovalResult{
		Approved:       approved,
		Grant:          grant,
		ConfigApproved: approval.ConfigApproved,
	})
}

// SendApprovalRequest sends an approval notification to the phone without blocking.
// It creates a PendingRequest, encrypts the metadata, sends the notification, and
// returns the PendingRequest so the caller can wait on ResultCh asynchronously.
// If a pending request for the same domain already exists (coalescing), it returns
// the existing one without sending a duplicate notification.
// The caller is responsible for calling pendingStore.Remove when done.
func (c *GatewayClient) SendApprovalRequest(metadata RequestMetadata) (*PendingRequest, error) {
	// Coalescing: check if there's already a pending request for this domain
	if existing := c.pendingStore.FindByDomain(metadata.Domain); existing != nil {
		atomic.AddInt32(&existing.WaiterCount, 1)
		return existing, nil
	}

	pr := &PendingRequest{
		ID:          metadata.RequestID,
		Domain:      metadata.Domain,
		Method:      metadata.Method,
		URL:         metadata.URL,
		CreatedAt:   time.Now(),
		ResultCh:    make(chan struct{}),
		WaiterCount: 1,
	}
	c.pendingStore.Add(pr)

	// Encrypt metadata for phone
	if c.phoneEncryptionKey == nil {
		c.pendingStore.Remove(pr.ID)
		return nil, fmt.Errorf("phone encryption key not configured")
	}
	encrypted, err := EncryptForPhone(metadata, c.phoneEncryptionKey)
	if err != nil {
		c.pendingStore.Remove(pr.ID)
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	// Send notification
	_, err = c.Notify(encrypted)
	if err != nil {
		c.pendingStore.Remove(pr.ID)
		return nil, fmt.Errorf("notify: %w", err)
	}

	return pr, nil
}

// RequestApproval sends an approval request to the phone and blocks until response or timeout.
func (c *GatewayClient) RequestApproval(ctx context.Context, metadata RequestMetadata) (ApprovalResult, error) {
	return c.RequestApprovalWithTimeout(ctx, metadata, c.approvalTimeout)
}

// RequestApprovalWithTimeout is like RequestApproval but uses the provided timeout.
func (c *GatewayClient) RequestApprovalWithTimeout(ctx context.Context, metadata RequestMetadata, timeout time.Duration) (ApprovalResult, error) {
	pr, err := c.SendApprovalRequest(metadata)
	if err != nil {
		return ApprovalResult{}, err
	}
	defer func() {
		atomic.AddInt32(&pr.WaiterCount, -1)
		c.pendingStore.Remove(pr.ID)
	}()

	// Wait for approval or timeout
	select {
	case <-pr.ResultCh:
		return pr.Result, nil
	case <-time.After(timeout):
		return ApprovalResult{}, fmt.Errorf("approval timeout after %v", timeout)
	case <-ctx.Done():
		return ApprovalResult{}, ctx.Err()
	}
}

// SendNotifyOnly sends an informational notification to the phone without blocking.
// The notification includes ApprovalRequired=false so the phone shows an info alert,
// not approval buttons. This is fire-and-forget; errors are logged.
func (c *GatewayClient) SendNotifyOnly(metadata RequestMetadata) {
	f := false
	metadata.ApprovalRequired = &f

	if c.phoneEncryptionKey == nil {
		slog.Error("notify-only: phone encryption key not configured")
		return
	}

	encrypted, err := EncryptForPhone(metadata, c.phoneEncryptionKey)
	if err != nil {
		slog.Error("notify-only: encrypt failed", "error", err)
		return
	}

	if _, err := c.Notify(encrypted); err != nil {
		slog.Error("notify-only: send failed", "error", err)
	}
}

// PollForApprovals polls the gateway for pending approvals via HTTP.
// This is a fallback when WebSocket is unavailable. It polls every 5 seconds
// until the context is cancelled (typically when the WebSocket reconnects).
func (c *GatewayClient) PollForApprovals(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	slog.Info("HTTP polling fallback started", "interval", "5s")

	for {
		select {
		case <-ctx.Done():
			slog.Info("HTTP polling fallback stopped")
			return
		case <-ticker.C:
			c.pollOnce(ctx)
		}
	}
}

func (c *GatewayClient) pollOnce(ctx context.Context) {
	url := c.gatewayURL + "/api/v1/pending?proxy_id=" + c.proxyID
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		slog.Error("poll: create request failed", "error", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return // context cancelled, not an error
		}
		slog.Error("poll: request failed", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		slog.Error("poll: non-200 response", "status", resp.StatusCode, "body", string(respBody))
		return
	}

	var messages []json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&messages); err != nil {
		slog.Error("poll: decode response failed", "error", err)
		return
	}

	for _, msg := range messages {
		c.handleWSMessage(msg)
	}
}

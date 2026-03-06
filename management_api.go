package main

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const deniedRingBufferSize = 100

// DeniedRequest records a request that was denied.
type DeniedRequest struct {
	Timestamp time.Time `json:"timestamp"`
	Method    string    `json:"method"`
	URL       string    `json:"url"`
	Domain    string    `json:"domain"`
	Path      string    `json:"path"`
	Reason    string    `json:"reason"`
}

// ManagementAPI handles /_switcheroo/v1/ endpoints.
type ManagementAPI struct {
	grantStore   GrantStore
	denyList     *DenyList
	mode         string
	startTime    time.Time
	policy       PolicyConfig
	deniedMu     sync.Mutex
	deniedReqs   []DeniedRequest
	deniedStart  int
	deniedCount  int
	declawClient      *GatewayClient
	grantRequestStore *GrantRequestStore
	onReload          func() error // called by POST /reload
	mcpHandler        *MCPHandler
	pairingSession    *PairingSession
	agentConfig       *AgentConfig
	routes            []Route // base routes for locked fields validation
}

func NewManagementAPI(grantStore GrantStore, denyList *DenyList, mode string, policy PolicyConfig) *ManagementAPI {
	return &ManagementAPI{
		grantStore: grantStore,
		denyList:   denyList,
		mode:       mode,
		startTime:  time.Now(),
		policy:     policy,
		deniedReqs: make([]DeniedRequest, deniedRingBufferSize),
	}
}

// RecordDenied adds a denied request to the ring buffer.
func (m *ManagementAPI) RecordDenied(req DeniedRequest) {
	m.deniedMu.Lock()
	defer m.deniedMu.Unlock()
	idx := (m.deniedStart + m.deniedCount) % deniedRingBufferSize
	if m.deniedCount < deniedRingBufferSize {
		m.deniedCount++
	} else {
		m.deniedStart = (m.deniedStart + 1) % deniedRingBufferSize
	}
	m.deniedReqs[idx] = req
}

// GetDenied returns all denied requests in order.
func (m *ManagementAPI) GetDenied() []DeniedRequest {
	m.deniedMu.Lock()
	defer m.deniedMu.Unlock()
	result := make([]DeniedRequest, 0, m.deniedCount)
	for i := 0; i < m.deniedCount; i++ {
		idx := (m.deniedStart + i) % deniedRingBufferSize
		result = append(result, m.deniedReqs[idx])
	}
	return result
}

func (m *ManagementAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// MCP endpoint (before v1 prefix strip)
	if r.URL.Path == "/_switcheroo/mcp" && m.mcpHandler != nil {
		m.mcpHandler.ServeHTTP(w, r)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/_switcheroo/v1")

	switch {
	case path == "/status" && r.Method == http.MethodGet:
		m.handleStatus(w, r)
	case path == "/grants" && r.Method == http.MethodGet:
		m.handleListGrants(w, r)
	case strings.HasPrefix(path, "/grants/") && r.Method == http.MethodDelete:
		id := strings.TrimPrefix(path, "/grants/")
		m.handleDeleteGrant(w, r, id)
	case path == "/policy" && r.Method == http.MethodGet:
		m.handleGetPolicy(w, r)
	case path == "/denied" && r.Method == http.MethodGet:
		m.handleGetDenied(w, r)
	case path == "/reload" && r.Method == http.MethodPost:
		m.handleReload(w, r)
	case path == "/pair/status" && r.Method == http.MethodGet:
		m.handlePairStatus(w, r)
	case path == "/pair/initiate" && r.Method == http.MethodPost:
		m.handlePairInitiate(w, r)
	case path == "/pair/session" && r.Method == http.MethodGet:
		m.handlePairSession(w, r)
	case path == "/agent-request" && r.Method == http.MethodPost:
		m.handleCreateGrantRequest(w, r)
	case path == "/agent-request" && r.Method == http.MethodGet:
		m.handleListGrantRequests(w, r)
	case strings.HasPrefix(path, "/agent-request/") && r.Method == http.MethodGet:
		id := strings.TrimPrefix(path, "/agent-request/")
		m.handleGetGrantRequest(w, r, id)
	case path == "/pending" && r.Method == http.MethodGet:
		m.handleListPending(w, r)
	case path == "/routes/dynamic" && r.Method == http.MethodGet:
		m.handleListDynamicRoutes(w, r)
	case strings.HasPrefix(path, "/routes/dynamic/") && r.Method == http.MethodDelete:
		id := strings.TrimPrefix(path, "/routes/dynamic/")
		m.handleDeleteDynamicRoute(w, r, id)
	default:
		http.NotFound(w, r)
	}
}

func (m *ManagementAPI) handleStatus(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"mode":             m.mode,
		"uptime":           time.Since(m.startTime).String(),
		"declaw_connected": m.declawClient != nil && m.declawClient.wsConn != nil,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (m *ManagementAPI) handleListGrants(w http.ResponseWriter, r *http.Request) {
	grants := m.grantStore.List()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(grants)
}

func (m *ManagementAPI) handleDeleteGrant(w http.ResponseWriter, r *http.Request, id string) {
	grants := m.grantStore.List()
	for _, g := range grants {
		if g.ID == id {
			if g.Source == "policy" {
				writeErrorResponse(w, http.StatusForbidden, ErrorResponse{
					Error:   "cannot_delete",
					Message: "Policy-sourced grants cannot be deleted via API",
				})
				return
			}
			m.grantStore.Remove(id)
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	http.NotFound(w, r)
}

func (m *ManagementAPI) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(m.policy)
}

func (m *ManagementAPI) handleGetDenied(w http.ResponseWriter, r *http.Request) {
	denied := m.GetDenied()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(denied)
}

func (m *ManagementAPI) handleReload(w http.ResponseWriter, r *http.Request) {
	if m.onReload == nil {
		writeErrorResponse(w, http.StatusNotImplemented, ErrorResponse{
			Error:   "reload_not_configured",
			Message: "Config reload is not configured",
		})
		return
	}

	if err := m.onReload(); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, ErrorResponse{
			Error:   "reload_failed",
			Message: err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (m *ManagementAPI) handlePairStatus(w http.ResponseWriter, r *http.Request) {
	paired := m.declawClient != nil &&
		m.declawClient.phoneSigningKey != nil &&
		m.declawClient.phoneEncryptionKey != nil
	resp := map[string]interface{}{
		"paired": paired,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (m *ManagementAPI) handlePairInitiate(w http.ResponseWriter, r *http.Request) {
	session, err := m.InitiatePairing()
	if err != nil {
		if grErr, ok := err.(*grantRequestError); ok {
			writeErrorResponse(w, grErr.Status, ErrorResponse{
				Error:   grErr.Code,
				Message: grErr.Message,
			})
			return
		}
		writeErrorResponse(w, http.StatusInternalServerError, ErrorResponse{
			Error:   "pairing_failed",
			Message: err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"pairing_url": session.PairingURL,
		"code":        session.Code,
		"qr_image":    base64.StdEncoding.EncodeToString(session.QRImage),
		"expires_at":  session.ExpiresAt.Format(time.RFC3339),
	})
}

func (m *ManagementAPI) handlePairSession(w http.ResponseWriter, r *http.Request) {
	if m.pairingSession == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":          "no_session",
			"phone_keys_set": false,
		})
		return
	}

	status := m.pairingSession.Status()
	paired := m.declawClient != nil &&
		m.declawClient.phoneSigningKey != nil &&
		m.declawClient.phoneEncryptionKey != nil

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":          status,
		"phone_keys_set": paired,
	})
}

// grantRequestBody is the JSON payload for POST /agent-request.
type grantRequestBody struct {
	Domain     string          `json:"domain"`
	PathPrefix string          `json:"path_prefix"`
	URL        string          `json:"url"`
	Methods    []string        `json:"methods"`
	Reason     string          `json:"reason"`
	Duration   string          `json:"duration"`
	OneShot    bool            `json:"one_shot"`
	Config     *ConfigProposal `json:"config,omitempty"`
}

func (m *ManagementAPI) isDeclawConnected() bool {
	return m.declawClient != nil && m.declawClient.wsConn != nil
}

// grantRequestError is a typed error returned by CreateGrantRequest.
type grantRequestError struct {
	Code    string // machine-readable error code
	Message string // human-readable message
	Status  int    // HTTP status code
}

func (e *grantRequestError) Error() string {
	return e.Message
}

// CreateGrantRequest validates and submits a grant request to DeClaw.
// Returns the request ID on success or a typed error.
func (m *ManagementAPI) CreateGrantRequest(body grantRequestBody) (string, error) {
	if !m.isDeclawConnected() {
		return "", &grantRequestError{
			Code:    "declaw_not_connected",
			Message: "DeClaw is not connected; pre-approval requires an active DeClaw connection",
			Status:  http.StatusServiceUnavailable,
		}
	}

	if m.grantRequestStore == nil {
		return "", &grantRequestError{
			Code:    "not_configured",
			Message: "Grant request store is not configured",
			Status:  http.StatusServiceUnavailable,
		}
	}

	// Validation
	if body.Domain == "" && body.URL == "" {
		return "", &grantRequestError{
			Code:    "missing_field",
			Message: "Either 'domain' or 'url' is required",
			Status:  http.StatusBadRequest,
		}
	}
	if body.Domain != "" && body.URL != "" {
		return "", &grantRequestError{
			Code:    "invalid_payload",
			Message: "'domain' and 'url' are mutually exclusive",
			Status:  http.StatusBadRequest,
		}
	}
	if body.Reason == "" {
		return "", &grantRequestError{
			Code:    "missing_field",
			Message: "'reason' is required",
			Status:  http.StatusBadRequest,
		}
	}

	// Validate duration if provided
	if body.Duration != "" {
		if _, err := time.ParseDuration(body.Duration); err != nil {
			return "", &grantRequestError{
				Code:    "invalid_duration",
				Message: "Invalid duration format: " + err.Error(),
				Status:  http.StatusBadRequest,
			}
		}
	}

	// Validate config proposal locked fields
	if body.Config != nil {
		if err := ValidateLockedFields(body.Config, m.routes); err != nil {
			return "", &grantRequestError{
				Code:    "route_locked",
				Message: err.Error(),
				Status:  http.StatusBadRequest,
			}
		}
	}

	requestID := generateRequestID()
	reason := sanitizeReason(body.Reason)

	gr := &GrantRequest{
		ID:             requestID,
		Status:         GrantRequestStatusPending,
		Domain:         body.Domain,
		PathPrefix:     body.PathPrefix,
		URL:            body.URL,
		Methods:        body.Methods,
		Reason:         reason,
		Duration:       body.Duration,
		OneShot:        body.OneShot,
		CreatedAt:      time.Now(),
		ConfigProposal: body.Config,
	}
	m.grantRequestStore.Add(gr)

	// Build metadata for phone notification
	domain := body.Domain
	if domain == "" {
		domain = body.URL
	}
	method := ""
	if len(body.Methods) > 0 {
		method = strings.Join(body.Methods, ",")
	}

	metadata := RequestMetadata{
		RequestID: requestID,
		ProxyID:   m.declawClient.proxyID,
		Domain:    domain,
		Method:    method,
		URL:       body.URL,
		Reason:    reason,
	}
	if body.Config != nil {
		metadata.HasConfigChange = true
		metadata.ConfigSummary = formatConfigSummary(body.Config)
		if body.Config.AddRoute != nil {
			pr := &ProposedRoute{
				Path:         body.Config.AddRoute.Path,
				Upstream:     body.Config.AddRoute.Upstream,
				ExtraHeaders: body.Config.AddRoute.ExtraHeaders,
			}
			auth := body.Config.AddRoute.UpstreamAuth
			if auth.Mode != "" {
				pr.UpstreamAuth = &ProposedAuth{
					Mode:   auth.Mode,
					Header: auth.Header,
					Value:  auth.Value,
					Token:  auth.Token,
				}
			}
			metadata.ProposedConfig = &ProposedConfig{AddRoute: pr}
			// Set has_agent_credentials when agent provides credential values
			if auth.Token != "" || auth.Value != "" || auth.ClientSecret != "" {
				metadata.HasAgentCreds = true
			}
		}
	}

	// Send non-blocking notification
	pr, err := m.declawClient.SendApprovalRequest(metadata)
	if err != nil {
		m.grantRequestStore.Resolve(requestID, GrantRequestStatusTimeout, nil)
		return "", &grantRequestError{
			Code:    "notification_failed",
			Message: "Failed to send notification: " + err.Error(),
			Status:  http.StatusInternalServerError,
		}
	}

	// Background goroutine to wait for result
	go m.waitForGrantRequestResult(pr, requestID)

	return requestID, nil
}

func (m *ManagementAPI) handleCreateGrantRequest(w http.ResponseWriter, r *http.Request) {
	var body grantRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_payload",
			Message: "Invalid JSON payload: " + err.Error(),
		})
		return
	}

	requestID, err := m.CreateGrantRequest(body)
	if err != nil {
		if grErr, ok := err.(*grantRequestError); ok {
			writeErrorResponse(w, grErr.Status, ErrorResponse{
				Error:   grErr.Code,
				Message: grErr.Message,
			})
			return
		}
		writeErrorResponse(w, http.StatusInternalServerError, ErrorResponse{
			Error:   "internal_error",
			Message: err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{
		"request_id": requestID,
		"status":     GrantRequestStatusPending,
	})
}

// waitForGrantRequestResult waits for the approval result and updates the grant request.
func (m *ManagementAPI) waitForGrantRequestResult(pr *PendingRequest, requestID string) {
	defer func() {
		atomic.AddInt32(&pr.WaiterCount, -1)
		m.declawClient.pendingStore.Remove(pr.ID)
	}()

	select {
	case <-pr.ResultCh:
		result := pr.Result
		if result.Approved && result.Grant != nil {
			m.grantStore.Add(result.Grant)
			m.grantRequestStore.Resolve(requestID, GrantRequestStatusApproved, result.Grant)
			slog.Info("grant-request resolved", "request_id", requestID, "action", "approved")

			// Apply config change only if the phone explicitly approved the config
			configApproved := result.ConfigApproved != nil && *result.ConfigApproved
			gr := m.grantRequestStore.Get(requestID)
			if gr != nil && gr.ConfigProposal != nil && gr.ConfigProposal.AddRoute != nil && configApproved && m.agentConfig != nil {
				meta := newAgentRouteMeta(requestID)
				if err := m.agentConfig.AddRoute(*gr.ConfigProposal.AddRoute, meta); err != nil {
					slog.Error("failed to save agent config", "request_id", requestID, "error", err)
				} else {
					slog.Info("agent config updated", "request_id", requestID, "route", gr.ConfigProposal.AddRoute.Path)
					if m.onReload != nil {
						if err := m.onReload(); err != nil {
							slog.Error("failed to reload after agent config change", "error", err)
						}
					}
				}
			}
		} else {
			m.grantRequestStore.Resolve(requestID, GrantRequestStatusDenied, nil)
			slog.Info("grant-request resolved", "request_id", requestID, "action", "denied")
		}
	case <-time.After(m.declawClient.approvalTimeout):
		m.grantRequestStore.Resolve(requestID, GrantRequestStatusTimeout, nil)
		slog.Warn("grant-request timeout", "request_id", requestID)
	}
}

func (m *ManagementAPI) handleGetGrantRequest(w http.ResponseWriter, r *http.Request, id string) {
	if m.grantRequestStore == nil {
		http.NotFound(w, r)
		return
	}

	gr := m.grantRequestStore.Get(id)
	if gr == nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(gr)
}

func (m *ManagementAPI) handleListGrantRequests(w http.ResponseWriter, r *http.Request) {
	if m.grantRequestStore == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]interface{}{})
		return
	}

	requests := m.grantRequestStore.List()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(requests)
}

// pendingRequestJSON is the JSON representation of a pending request.
type pendingRequestJSON struct {
	ID        string    `json:"id"`
	Domain    string    `json:"domain"`
	Method    string    `json:"method"`
	URL       string    `json:"url,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func (m *ManagementAPI) handleListPending(w http.ResponseWriter, r *http.Request) {
	if m.declawClient == nil || m.declawClient.pendingStore == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]interface{}{})
		return
	}

	pending := m.declawClient.pendingStore.List()
	result := make([]pendingRequestJSON, 0, len(pending))
	for _, pr := range pending {
		result = append(result, pendingRequestJSON{
			ID:        pr.ID,
			Domain:    pr.Domain,
			Method:    pr.Method,
			URL:       pr.URL,
			CreatedAt: pr.CreatedAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (m *ManagementAPI) handleListDynamicRoutes(w http.ResponseWriter, r *http.Request) {
	if m.agentConfig == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]interface{}{})
		return
	}

	routes := m.agentConfig.ListRoutes()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(routes)
}

func (m *ManagementAPI) handleDeleteDynamicRoute(w http.ResponseWriter, r *http.Request, id string) {
	if m.agentConfig == nil {
		http.NotFound(w, r)
		return
	}

	removed, err := m.agentConfig.RemoveRoute(id)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, ErrorResponse{
			Error:   "save_failed",
			Message: "Failed to save agent config: " + err.Error(),
		})
		return
	}
	if !removed {
		http.NotFound(w, r)
		return
	}

	// Trigger reload to remove the route from active routing
	if m.onReload != nil {
		if err := m.onReload(); err != nil {
			slog.Error("failed to reload after dynamic route deletion", "error", err)
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

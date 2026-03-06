package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"
)

const (
	mcpProtocolVersion = "2025-03-26"
)

// JSON-RPC 2.0 types

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"` // null for notifications
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// MCP types

type mcpServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type mcpInitializeResult struct {
	ProtocolVersion string            `json:"protocolVersion"`
	Capabilities    mcpCapabilities   `json:"capabilities"`
	ServerInfo      mcpServerInfo     `json:"serverInfo"`
}

type mcpCapabilities struct {
	Tools *mcpToolCapability `json:"tools,omitempty"`
}

type mcpToolCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

type mcpTool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema interface{} `json:"inputSchema"`
}

type mcpToolsListResult struct {
	Tools []mcpTool `json:"tools"`
}

type mcpToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

type mcpToolContent struct {
	Type    string `json:"type"`
	Text    string `json:"text"`
}

type mcpToolResult struct {
	Content []mcpToolContent `json:"content"`
	IsError bool             `json:"isError,omitempty"`
}

// MCPHandler handles MCP Streamable HTTP requests.
type MCPHandler struct {
	mgmtAPI *ManagementAPI
}

// NewMCPHandler creates a new MCPHandler.
func NewMCPHandler(mgmtAPI *ManagementAPI) *MCPHandler {
	return &MCPHandler{mgmtAPI: mgmtAPI}
}

func (h *MCPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeErrorResponse(w, http.StatusMethodNotAllowed, ErrorResponse{
			Error:   "method_not_allowed",
			Message: "The MCP endpoint only accepts POST requests",
		})
		return
	}

	ct := r.Header.Get("Content-Type")
	if ct != "application/json" && ct != "" {
		writeErrorResponse(w, http.StatusUnsupportedMediaType, ErrorResponse{
			Error:   "unsupported_media_type",
			Message: "The MCP endpoint requires Content-Type: application/json",
		})
		return
	}

	var req jsonRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONRPC(w, http.StatusOK, jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      nil,
			Error: &jsonRPCError{
				Code:    -32700,
				Message: "Parse error: " + err.Error(),
			},
		})
		return
	}

	// Notifications have null/absent id
	if isNotification(req.ID) {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	switch req.Method {
	case "initialize":
		h.handleInitialize(w, req)
	case "tools/list":
		h.handleToolsList(w, req)
	case "tools/call":
		h.handleToolsCall(w, req)
	default:
		writeJSONRPC(w, http.StatusOK, jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &jsonRPCError{
				Code:    -32601,
				Message: "Method not found: " + req.Method,
			},
		})
	}
}

func (h *MCPHandler) handleInitialize(w http.ResponseWriter, req jsonRPCRequest) {
	writeJSONRPC(w, http.StatusOK, jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: mcpInitializeResult{
			ProtocolVersion: mcpProtocolVersion,
			Capabilities: mcpCapabilities{
				Tools: &mcpToolCapability{},
			},
			ServerInfo: mcpServerInfo{
				Name:    "switcheroo",
				Version: "1.0.0",
			},
		},
	})
}

func (h *MCPHandler) handleToolsList(w http.ResponseWriter, req jsonRPCRequest) {
	tools := []mcpTool{
		{
			Name:        "request_api_access",
			Description: "Request pre-approval for API access through switcheroo proxy. Submits a grant request to DeClaw for human approval.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"domain": map[string]interface{}{
						"type":        "string",
						"description": "Target API domain (e.g. api.stripe.com). Mutually exclusive with 'url'.",
					},
					"url": map[string]interface{}{
						"type":        "string",
						"description": "Specific URL to access. Mutually exclusive with 'domain'.",
					},
					"path_prefix": map[string]interface{}{
						"type":        "string",
						"description": "Path prefix to restrict access to (e.g. /v1/charges).",
					},
					"methods": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "HTTP methods to allow (e.g. [\"GET\", \"POST\"]). Empty means all methods.",
					},
					"reason": map[string]interface{}{
						"type":        "string",
						"description": "Why this access is needed. Shown to the human approver.",
					},
					"duration": map[string]interface{}{
						"type":        "string",
						"description": "Requested grant duration (e.g. \"1h\", \"30m\"). Go duration format.",
					},
					"one_shot": map[string]interface{}{
						"type":        "boolean",
						"description": "If true, grant is consumed after one use.",
					},
				},
				"required": []string{"reason"},
				"oneOf": []interface{}{
					map[string]interface{}{"required": []string{"domain"}},
					map[string]interface{}{"required": []string{"url"}},
				},
			},
		},
		{
			Name:        "check_access_request",
			Description: "Check the status of a previously submitted access request.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"request_id": map[string]interface{}{
						"type":        "string",
						"description": "The request ID returned by request_api_access.",
					},
				},
				"required": []string{"request_id"},
			},
		},
		{
			Name:        "initiate_pairing",
			Description: "Initiate pairing with a DeClaw phone app. Returns a pairing URL (deep link), a 6-digit code for manual entry, and a QR code image (base64 PNG). Present whichever is appropriate for the user's context.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name:        "check_pairing_status",
			Description: "Check the status of the current pairing session. Returns no_session, pending, success, or expired.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
	}

	writeJSONRPC(w, http.StatusOK, jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  mcpToolsListResult{Tools: tools},
	})
}

func (h *MCPHandler) handleToolsCall(w http.ResponseWriter, req jsonRPCRequest) {
	var params mcpToolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		writeJSONRPC(w, http.StatusOK, jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &jsonRPCError{
				Code:    -32602,
				Message: "Invalid params: " + err.Error(),
			},
		})
		return
	}

	switch params.Name {
	case "request_api_access":
		h.handleRequestAPIAccess(w, req.ID, params.Arguments)
	case "check_access_request":
		h.handleCheckAccessRequest(w, req.ID, params.Arguments)
	case "initiate_pairing":
		h.handleInitiatePairing(w, req.ID)
	case "check_pairing_status":
		h.handleCheckPairingStatus(w, req.ID)
	default:
		writeJSONRPC(w, http.StatusOK, jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &jsonRPCError{
				Code:    -32602,
				Message: "Unknown tool: " + params.Name,
			},
		})
	}
}

func (h *MCPHandler) handleRequestAPIAccess(w http.ResponseWriter, id json.RawMessage, args json.RawMessage) {
	var body grantRequestBody
	if args != nil {
		if err := json.Unmarshal(args, &body); err != nil {
			writeJSONRPC(w, http.StatusOK, jsonRPCResponse{
				JSONRPC: "2.0",
				ID:      id,
				Result: mcpToolResult{
					Content: []mcpToolContent{{Type: "text", Text: "Invalid arguments: " + err.Error()}},
					IsError: true,
				},
			})
			return
		}
	}

	requestID, err := h.mgmtAPI.CreateGrantRequest(body)
	if err != nil {
		writeJSONRPC(w, http.StatusOK, jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Result: mcpToolResult{
				Content: []mcpToolContent{{Type: "text", Text: err.Error()}},
				IsError: true,
			},
		})
		return
	}

	result, _ := json.Marshal(map[string]string{
		"request_id": requestID,
		"status":     "pending",
	})

	writeJSONRPC(w, http.StatusOK, jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: mcpToolResult{
			Content: []mcpToolContent{{Type: "text", Text: string(result)}},
		},
	})
}

func (h *MCPHandler) handleCheckAccessRequest(w http.ResponseWriter, id json.RawMessage, args json.RawMessage) {
	var params struct {
		RequestID string `json:"request_id"`
	}
	if args != nil {
		if err := json.Unmarshal(args, &params); err != nil {
			writeJSONRPC(w, http.StatusOK, jsonRPCResponse{
				JSONRPC: "2.0",
				ID:      id,
				Result: mcpToolResult{
					Content: []mcpToolContent{{Type: "text", Text: "Invalid arguments: " + err.Error()}},
					IsError: true,
				},
			})
			return
		}
	}

	if params.RequestID == "" {
		writeJSONRPC(w, http.StatusOK, jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Result: mcpToolResult{
				Content: []mcpToolContent{{Type: "text", Text: "request_id is required"}},
				IsError: true,
			},
		})
		return
	}

	if h.mgmtAPI.grantRequestStore == nil {
		writeJSONRPC(w, http.StatusOK, jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Result: mcpToolResult{
				Content: []mcpToolContent{{Type: "text", Text: "Grant request store is not configured"}},
				IsError: true,
			},
		})
		return
	}

	gr := h.mgmtAPI.grantRequestStore.Get(params.RequestID)
	if gr == nil {
		writeJSONRPC(w, http.StatusOK, jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Result: mcpToolResult{
				Content: []mcpToolContent{{Type: "text", Text: "Grant request not found: " + params.RequestID}},
				IsError: true,
			},
		})
		return
	}

	result, _ := json.Marshal(gr)

	writeJSONRPC(w, http.StatusOK, jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: mcpToolResult{
			Content: []mcpToolContent{{Type: "text", Text: string(result)}},
		},
	})
}

func (h *MCPHandler) handleInitiatePairing(w http.ResponseWriter, id json.RawMessage) {
	session, err := h.mgmtAPI.InitiatePairing()
	if err != nil {
		writeJSONRPC(w, http.StatusOK, jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Result: mcpToolResult{
				Content: []mcpToolContent{{Type: "text", Text: err.Error()}},
				IsError: true,
			},
		})
		return
	}

	result, _ := json.Marshal(map[string]string{
		"pairing_url": session.PairingURL,
		"code":        session.Code,
		"qr_image":    base64.StdEncoding.EncodeToString(session.QRImage),
		"expires_at":  session.ExpiresAt.Format(time.RFC3339),
	})

	writeJSONRPC(w, http.StatusOK, jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: mcpToolResult{
			Content: []mcpToolContent{{Type: "text", Text: string(result)}},
		},
	})
}

func (h *MCPHandler) handleCheckPairingStatus(w http.ResponseWriter, id json.RawMessage) {
	status := "no_session"
	if h.mgmtAPI.pairingSession != nil {
		status = h.mgmtAPI.pairingSession.Status()
	}

	result, _ := json.Marshal(map[string]string{
		"status": status,
	})

	writeJSONRPC(w, http.StatusOK, jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: mcpToolResult{
			Content: []mcpToolContent{{Type: "text", Text: string(result)}},
		},
	})
}

// isNotification returns true if the JSON-RPC request has no id (notification).
func isNotification(id json.RawMessage) bool {
	return id == nil || string(id) == "null" || string(id) == ""
}

func writeJSONRPC(w http.ResponseWriter, status int, resp jsonRPCResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}

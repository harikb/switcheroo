# Switcheroo

A grant-based gated reverse proxy written in Go. Switcheroo sits between your AI agents and upstream APIs, controlling which domains and endpoints agents can access and injecting real credentials into approved requests.

It is designed to work with [DeClaw](https://declawapp.com) for phone-based human approval and [OpenClaw](https://github.com/openclaw/openclaw) as the AI assistant platform. Real API keys and OAuth tokens stay with the proxy; agents get access controlled by policy rules, grants, and optional human approval via the DeClaw phone app.

## Features

- **Two operating modes:**
  - `passthrough` — proxy all matched requests without grant checks
  - `gated` — require a grant (from policy, DeClaw approval, or pre-approval) before forwarding
- **Path-based routing** with longest-prefix matching to multiple upstream APIs
- **Forward proxy** — HTTP CONNECT tunneling and absolute-URI proxying for domains not covered by named routes, also subject to grant checks in gated mode
- **Policy rules** — declarative allow/deny lists with domain wildcards, path prefixes, HTTP method filtering, expiration, and one-shot grants
- **DeClaw integration** — phone-based human approval via WebSocket; requests without a matching grant are held until the user approves or denies from their phone
- **MCP endpoint** (`/_switcheroo/mcp`) — Model Context Protocol server that agents can call to pre-request access (`request_api_access`), check status (`check_access_request`), and initiate phone pairing (`initiate_pairing`)
- **Management API** (`/_switcheroo/v1/`) — REST endpoints for status, grants, policy, denied requests, reload, pairing, pending requests, and dynamic routes (restricted to loopback and configured CIDRs)
- **Four upstream authentication modes:**
  - `static_bearer` — fixed Bearer token
  - `static_api_key` — fixed API key in a custom header
  - `oauth_refresh_token` — OAuth 2.0 refresh token flow with automatic renewal
  - `oauth_client_credentials` — OAuth 2.0 client credentials grant
- **Automatic token refresh** — OAuth tokens are refreshed before expiry and on upstream 401 responses
- **Token and grant persistence** — OAuth token state saved to disk; grants persisted in SQLite (`modernc.org/sqlite`, pure Go)
- **Route approval modes** — per-route control: `required` (default in gated mode), `auto` (skip gating), `notify-only` (inform DeClaw but don't block)
- **Dynamic routes** — agents can propose new routes via MCP; approved routes are persisted to a separate agent config file
- **Config hot-reload** — SIGHUP, `POST /_switcheroo/v1/reload`, or automatic file-watch triggers policy reload without restart
- **Inbound authentication** — optionally validate incoming requests via a shared secret header
- **Extra headers** — inject additional headers per route (e.g., API version headers)
- **Environment variable expansion** — use `${VAR_NAME}` in YAML config values
- **Locked routes** — prevent agents from modifying specific route fields via config proposals
- **Minimal footprint** — single binary, builds to a scratch Docker image

## Security Considerations

**Switcheroo is not a public-facing service.** It is designed to run on a trusted network (e.g., localhost, a private Docker network, or a VPN) where only authorized clients can reach it.

- **Network isolation is your primary security boundary.** Clients that can reach the proxy can use the upstream credentials. Do not expose switcheroo to the public internet.
- **Gated mode with DeClaw provides human-in-the-loop approval.** In gated mode, requests without a matching grant are blocked until approved via the DeClaw phone app. This is the recommended mode for AI agent deployments.
- **Inbound auth is defense-in-depth, not a substitute for network controls.** The optional `inbound_auth` header check provides an additional layer but should not be relied upon as the sole access control mechanism.
- **Management API is restricted.** The `/_switcheroo/` endpoints are only accessible from loopback addresses and explicitly configured CIDRs (`management_api_allowed_cidrs`).
- **Credentials are stored in plaintext.** The YAML config (via environment variables) and the token state file contain sensitive secrets. Protect these files with appropriate filesystem permissions.
- **Grant database contains live permissions.** The SQLite grant DB and token state file should not be accessible to untrusted users or processes.
- **TLS termination is not handled by switcheroo.** If you need encrypted transport between clients and the proxy, place it behind a TLS-terminating reverse proxy or use a tunnel.

## Quick Start

### Build from source

```bash
go build -o switcheroo .
```

### Run (standalone, gated mode)

```bash
./switcheroo -config switcheroo.yaml
```

### Run (with DeClaw phone approval)

```bash
# First register with DeClaw gateway (one-time setup)
./switcheroo -config switcheroo.yaml -register

# Then pair with your phone (one-time setup)
./switcheroo -config switcheroo.yaml -pair

# Run normally
./switcheroo -config switcheroo.yaml
```

[![DeClaw Demo](https://img.youtube.com/vi/KTYLRBm7_PY/maxresdefault.jpg)](https://www.youtube.com/watch?v=KTYLRBm7_PY)

### Docker

```bash
docker build -t switcheroo .

docker run -d \
  -p 4000:4000 \
  -v $(pwd)/switcheroo.yaml:/etc/switcheroo/switcheroo.yaml:ro \
  -v switcheroo-data:/data \
  switcheroo
```

The Docker image is built from `scratch` and contains only the static binary and CA certificates.

## Configuration

Switcheroo is configured via a YAML file. All values support environment variable expansion using `${VAR_NAME}` syntax.

### Standalone Example (gated mode with policy rules)

```yaml
server:
  listen: ":4000"
  mode: gated
  grant_db: "grants.db"
  token_state_file: "token_state.json"

policy:
  allow:
    - domain: "httpbin.org"
    - domain: "jsonplaceholder.typicode.com"
  deny:
    - domain: "*.evil.com"

routes:
  - path: /httpbin
    upstream: https://httpbin.org
    upstream_auth:
      mode: ""

  - path: /jsonplaceholder
    upstream: https://jsonplaceholder.typicode.com
    upstream_auth:
      mode: ""

forward_proxy:
  enabled: true
  allowed_ports: [80, 443]
```

### DeClaw Example (phone-based approval)

```yaml
server:
  listen: ":4000"
  mode: gated
  grant_db: "grants.db"
  token_state_file: "token_state.json"

policy:
  deny:
    - domain: "*.evil.com"

routes:
  - path: /httpbin
    upstream: https://httpbin.org
    upstream_auth:
      mode: ""

forward_proxy:
  enabled: true
  allowed_ports: [80, 443]

declaw:
  enabled: true
  gateway_url: "https://declawapp.com"
  proxy_id: "prx_..."
  proxy_api_key: "dk_live_..."
  proxy_encryption_key_file: "proxy.key"
```

### Route Authentication Examples

```yaml
routes:
  # --- Static Bearer Token ---
  - path: /anthropic
    upstream: https://api.anthropic.com
    inbound_auth:
      header: x-api-key
      value: ${ANTHROPIC_INTERNAL_SECRET}
      strip: true
    upstream_auth:
      mode: static_bearer
      token: ${ANTHROPIC_MAX_TOKEN}
    extra_headers:
      anthropic-beta: "oauth-2025-04-20"

  # --- Static API Key ---
  - path: /weather
    upstream: https://api.openweathermap.org
    upstream_auth:
      mode: static_api_key
      header: x-api-key
      value: ${WEATHER_API_KEY}

  # --- OAuth with Refresh Token (auto-refresh) ---
  - path: /strava
    upstream: https://www.strava.com
    upstream_auth:
      mode: oauth_refresh_token
      client_id: ${STRAVA_CLIENT_ID}
      client_secret: ${STRAVA_CLIENT_SECRET}
      token_url: https://www.strava.com/oauth/token
      access_token: ${STRAVA_ACCESS_TOKEN}
      refresh_token: ${STRAVA_REFRESH_TOKEN}

  # --- OAuth Client Credentials (fully automatic) ---
  - path: /spotify
    upstream: https://api.spotify.com
    upstream_auth:
      mode: oauth_client_credentials
      client_id: ${SPOTIFY_CLIENT_ID}
      client_secret: ${SPOTIFY_CLIENT_SECRET}
      token_url: https://accounts.spotify.com/api/token
      scopes: [user-read-recently-played]

  # --- No auth (proxy only, gating still applies in gated mode) ---
  - path: /httpbin
    upstream: https://httpbin.org
    upstream_auth:
      mode: ""
```

### Configuration Reference

#### `server`

| Field | Description | Required | Default |
|---|---|---|---|
| `listen` | Address and port to listen on | No | `:4000` |
| `mode` | Operating mode: `passthrough` or `gated` | **Yes** | — |
| `grant_db` | Path to SQLite grant database | **Yes** | — |
| `token_state_file` | Path to persist OAuth token state | No | *(none)* |
| `approval_timeout` | Default timeout for DeClaw approval requests (Go duration) | No | *(built-in default)* |
| `management_api_allowed_cidrs` | List of CIDRs allowed to access `/_switcheroo/` (loopback is always allowed) | No | *(loopback only)* |
| `agent_config_path` | Path to agent config file for dynamic routes | No | *(none)* |

#### `routes[]`

| Field | Description | Required |
|---|---|---|
| `path` | URL path prefix to match (e.g., `/anthropic`) | Yes |
| `upstream` | Base URL of the upstream service | Yes |
| `inbound_auth` | Inbound request validation (see below) | No |
| `upstream_auth` | Upstream authentication config (see below) | No |
| `extra_headers` | Map of additional headers to add to upstream requests | No |
| `approval` | Approval mode: `required`, `auto`, or `notify-only` | No (defaults to `required` in gated mode) |
| `approval_timeout` | Per-route override for approval timeout (Go duration) | No |
| `locked` | If `true`, the entire route cannot be modified by agents | No |
| `locked_fields` | List of fields agents cannot modify: `upstream`, `upstream_auth`, `inbound_auth`, `extra_headers`, `path`, `none` | No |

#### `routes[].inbound_auth`

| Field | Description |
|---|---|
| `header` | Header name to check on incoming requests |
| `value` | Expected header value |
| `strip` | If `true`, remove this header before forwarding upstream |

#### `routes[].upstream_auth`

**Mode: `static_bearer`**

| Field | Description |
|---|---|
| `mode` | `static_bearer` |
| `token` | Bearer token value |

Adds `Authorization: Bearer <token>` to upstream requests.

**Mode: `static_api_key`**

| Field | Description |
|---|---|
| `mode` | `static_api_key` |
| `header` | Header name (e.g., `x-api-key`) |
| `value` | API key value |

Adds a custom header with the API key value.

**Mode: `oauth_refresh_token`**

| Field | Description |
|---|---|
| `mode` | `oauth_refresh_token` |
| `client_id` | OAuth client ID |
| `client_secret` | OAuth client secret |
| `token_url` | Token endpoint URL |
| `access_token` | Initial access token (used until first refresh) |
| `refresh_token` | Refresh token |

Automatically refreshes the access token when it expires. Both access and refresh tokens are updated on each refresh cycle and persisted to disk.

**Mode: `oauth_client_credentials`**

| Field | Description |
|---|---|
| `mode` | `oauth_client_credentials` |
| `client_id` | OAuth client ID |
| `client_secret` | OAuth client secret |
| `token_url` | Token endpoint URL |
| `scopes` | List of OAuth scopes to request |

Obtains tokens automatically using the client credentials grant. No user interaction required.

**Mode: `""` (empty)**

No upstream authentication. The request is forwarded as-is (after stripping inbound auth headers if configured). Useful for public APIs or when you only need gating without credential injection.

#### `policy`

Policy rules define declarative allow/deny lists. Deny rules take absolute priority over grants.

| Field | Description |
|---|---|
| `allow` | List of policy rules that generate grants on startup |
| `deny` | List of policy rules that block matching requests regardless of grants |

**Policy rule fields:**

| Field | Description |
|---|---|
| `domain` | Domain to match (supports `*.example.com` wildcards) |
| `path_prefix` | Path prefix to restrict the rule to |
| `url` | Exact URL to match (mutually exclusive with `domain`) |
| `method` | Single HTTP method to restrict to |
| `methods` | List of HTTP methods to restrict to |
| `expires` | Duration after which the grant expires (Go duration, e.g., `24h`) |
| `one_shot` | If `true`, the grant is consumed after one use |

#### `forward_proxy`

| Field | Description | Default |
|---|---|---|
| `enabled` | Enable forward proxy (HTTP CONNECT and absolute-URI) | `false` |
| `allowed_ports` | List of allowed destination ports | `[80, 443]` when enabled |
| `bypass` | List of hostnames that bypass grant checks | *(none)* |

#### `declaw`

| Field | Description |
|---|---|
| `enabled` | Enable DeClaw integration |
| `gateway_url` | DeClaw gateway URL (required when enabled) |
| `proxy_id` | Proxy ID (set by `-register`) |
| `proxy_api_key` | Proxy API key (set by `-register`) |
| `proxy_encryption_key_file` | Path to proxy encryption key file (set by `-register`) |
| `phone_signing_key` | Phone signing public key (set by `-pair`) |
| `phone_encryption_key` | Phone encryption public key (set by `-pair`) |

## How It Works

### Passthrough Mode

```
Client                    Switcheroo                   Upstream API
  |                           |                             |
  |  GET /anthropic/v1/chat   |                             |
  |-------------------------->|                             |
  |                           |  match route /anthropic     |
  |                           |  validate inbound auth      |
  |                           |  strip prefix, add creds    |
  |                           |                             |
  |                           |  GET /v1/chat               |
  |                           |  Authorization: Bearer ...  |
  |                           |---------------------------->|
  |                           |                             |
  |                           |         200 OK              |
  |                           |<----------------------------|
  |        200 OK             |                             |
  |<--------------------------|                             |
```

### Gated Mode (with DeClaw)

```
Agent                     Switcheroo                   DeClaw Phone
  |                           |                             |
  |  GET /httpbin/get         |                             |
  |-------------------------->|                             |
  |                           |  no matching grant          |
  |                           |  send approval request ---->|
  |                           |                             |
  |                           |  (agent waits...)           |
  |                           |                             |
  |                           |  <-- user taps "approve"    |
  |                           |  grant created & stored     |
  |                           |                             |
  |        200 OK             |                             |
  |<--------------------------|                             |
```

### Request Flow

1. Client sends a request to a switcheroo route (e.g., `/httpbin/get`)
2. Management API requests (`/_switcheroo/`) are routed to the management API
3. Forward proxy requests (CONNECT or absolute URI) are routed to the forward proxy
4. Otherwise, the longest path prefix is matched to find the route
5. If `inbound_auth` is configured, the request header is validated (401 on failure)
6. **In gated mode:** the deny list is checked, then a matching grant is required. If no grant exists and DeClaw is connected, an approval request is sent to the phone and the request blocks until approved, denied, or timed out
7. The route path prefix is stripped from the URL
8. Upstream credentials are injected based on the auth mode
9. Extra headers are added
10. The request is forwarded to the upstream service
11. If the upstream returns 401 and the auth mode supports refresh, tokens are refreshed and the request is retried once
12. The response is proxied back to the client

## Management API

All management endpoints are under `/_switcheroo/` and restricted to loopback addresses and configured CIDRs.

| Endpoint | Method | Description |
|---|---|---|
| `/_switcheroo/v1/status` | GET | Proxy status (mode, uptime, DeClaw connection) |
| `/_switcheroo/v1/grants` | GET | List all active grants |
| `/_switcheroo/v1/grants/:id` | DELETE | Remove a grant (policy grants cannot be deleted) |
| `/_switcheroo/v1/policy` | GET | Current policy rules |
| `/_switcheroo/v1/denied` | GET | Recent denied requests (ring buffer, last 100) |
| `/_switcheroo/v1/reload` | POST | Trigger config reload |
| `/_switcheroo/v1/pending` | GET | List pending DeClaw approval requests |
| `/_switcheroo/v1/agent-request` | POST | Submit a grant request for DeClaw approval |
| `/_switcheroo/v1/agent-request` | GET | List grant requests |
| `/_switcheroo/v1/agent-request/:id` | GET | Check grant request status |
| `/_switcheroo/v1/routes/dynamic` | GET | List agent-added dynamic routes |
| `/_switcheroo/v1/routes/dynamic/:id` | DELETE | Remove a dynamic route |
| `/_switcheroo/v1/pair/status` | GET | Phone pairing status |
| `/_switcheroo/v1/pair/initiate` | POST | Start phone pairing flow |
| `/_switcheroo/v1/pair/session` | GET | Current pairing session status |
| `/_switcheroo/mcp` | POST | MCP (Model Context Protocol) endpoint for agent tools |

### MCP Tools

The MCP endpoint exposes these tools for AI agents:

| Tool | Description |
|---|---|
| `request_api_access` | Pre-request access to a domain or URL with a reason; sends approval to DeClaw phone |
| `check_access_request` | Poll the status of a previously submitted access request |
| `initiate_pairing` | Start pairing with a DeClaw phone app (returns QR code, deep link, and 6-digit code) |
| `check_pairing_status` | Check pairing session status |

## Using with OpenClaw

Point your [OpenClaw](https://github.com/openclaw/openclaw) gateway's API base URL at switcheroo instead of the upstream service directly. For example, configure OpenClaw to use `http://localhost:4000/anthropic` as the Anthropic API endpoint. OpenClaw sends requests without real credentials (or with a local shared secret), and switcheroo handles the rest.

This keeps production API keys out of the OpenClaw configuration and centralizes credential management in one place.

## License

See [LICENSE](LICENSE) for details.

### Sample Usage

#### Inside your OpenClaw network

  % ../../../switcheroo -config switcheroo.yaml
  {"time":"2026-03-06T13:49:07.198693-08:00","level":"INFO","msg":"loaded routes","count":1,"mode":"gated"}
  {"time":"2026-03-06T13:49:07.198835-08:00","level":"INFO","msg":"route","path":"/httpbin","upstream":"https://httpbin.org","auth_mode":""}
  {"time":"2026-03-06T13:49:07.202794-08:00","level":"INFO","msg":"grant store opened","backend":"sqlite","path":"grants.db"}
  {"time":"2026-03-06T13:49:07.202816-08:00","level":"INFO","msg":"forward proxy enabled","allowed_ports":[80,443]}
  {"time":"2026-03-06T13:49:07.203733-08:00","level":"INFO","msg":"declaw connected","gateway_url":"https://declawapp.com","proxy_id":"prx_82c5fbec71045ccc"}
  {"time":"2026-03-06T13:49:07.203767-08:00","level":"INFO","msg":"listening","addr":":4000"}
  {"time":"2026-03-06T13:49:07.204282-08:00","level":"INFO","msg":"watching config file for changes","path":"switcheroo.yaml"}
  {"time":"2026-03-06T13:49:07.853102-08:00","level":"INFO","msg":"declaw websocket connected","gateway_url":"https://declawapp.com"}

#### Inside your OpenClaw network

Sample pre-approval post from your Agent for external access

    % curl -s -X POST localhost:4000/_switcheroo/mcp \
      -H "Content-Type: application/json" \
      -d '{
        "jsonrpc":"2.0","id":20,
        "method":"tools/call",
        "params":{
          "name":"request_api_access",
          "arguments":{
            "domain":"jsonplaceholder.typicode.com",
            "reason":"Need to fetch sample TODO data",
            "duration":"30m"
          }
        }
      }' | jq .
    {
      "jsonrpc": "2.0",
      "id": 20,
      "result": {
        "content": [
          {
            "type": "text",
            "text": "{\"request_id\":\"a3fa510ce5f78e1b3cd5772ae6e5910a\",\"status\":\"pending\"}"
          }
        ]
      }
    }

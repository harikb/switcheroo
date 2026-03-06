# Switcheroo

A lightweight credential-swapping reverse proxy written in Go. Switcheroo sits between your clients and upstream APIs, injecting real credentials into requests so that clients never need to handle secrets directly.

It is designed to work with [OpenClaw](https://github.com/openclaw/openclaw) and similar personal AI assistant platforms, where you want your local agent to access multiple APIs without embedding credentials in the client. Real API keys and OAuth tokens stay with the proxy; clients get auth-free access protected only by network restrictions and optional inbound header validation.

## Features

- **Path-based routing** with longest-prefix matching to multiple upstream APIs
- **Four authentication modes** for upstream services:
  - `static_bearer` — fixed Bearer token
  - `static_api_key` — fixed API key in a custom header
  - `oauth_refresh_token` — OAuth 2.0 refresh token flow with automatic renewal
  - `oauth_client_credentials` — OAuth 2.0 client credentials grant with automatic token acquisition
- **Automatic token refresh** — OAuth tokens are refreshed 30 seconds before expiry and on upstream 401 responses
- **Token persistence** — OAuth token state is saved to disk (atomic writes) and restored on restart
- **Inbound authentication** — optionally validate incoming requests via a shared secret header
- **Header stripping** — remove inbound auth headers before forwarding to upstream
- **Extra headers** — inject additional headers per route (e.g., API version headers)
- **Environment variable expansion** — use `${VAR_NAME}` in YAML config values
- **Minimal footprint** — single binary, single dependency (`gopkg.in/yaml.v3`), builds to a scratch Docker image

## Security Considerations

**Switcheroo is not a public-facing service.** It is designed to run on a trusted network (e.g., localhost, a private Docker network, or a VPN) where only authorized clients can reach it.

- **Network isolation is your primary security boundary.** Clients that can reach the proxy can use the upstream credentials. Do not expose switcheroo to the public internet.
- **Inbound auth is defense-in-depth, not a substitute for network controls.** The optional `inbound_auth` header check provides an additional layer but should not be relied upon as the sole access control mechanism.
- **Credentials are stored in plaintext.** The YAML config (via environment variables) and the token state file contain sensitive secrets. Protect these files with appropriate filesystem permissions.
- **Token state file contains live OAuth tokens.** Ensure the `token_state_file` path is not accessible to untrusted users or processes.
- **TLS termination is not handled by switcheroo.** If you need encrypted transport between clients and the proxy, place it behind a TLS-terminating reverse proxy or use a tunnel.

## Quick Start

### Build from source

```bash
go build -o switcheroo .
```

### Run

```bash
export ANTHROPIC_INTERNAL_SECRET="my-local-secret"
export ANTHROPIC_MAX_TOKEN="sk-ant-..."
# ... set other env vars as needed

./switcheroo --config switcheroo.yaml
```

### Docker

```bash
docker build -t switcheroo .

docker run -d \
  -p 4000:4000 \
  -v $(pwd)/switcheroo.yaml:/etc/switcheroo/switcheroo.yaml:ro \
  -v switcheroo-data:/data \
  -e ANTHROPIC_INTERNAL_SECRET="my-local-secret" \
  -e ANTHROPIC_MAX_TOKEN="sk-ant-..." \
  switcheroo
```

The Docker image is built from `scratch` and contains only the static binary and CA certificates.

## Configuration

Switcheroo is configured via a single YAML file. All values support environment variable expansion using `${VAR_NAME}` syntax.

### Full Example

```yaml
server:
  listen: ":4000"
  token_state_file: /data/switcheroo-tokens.json

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
      anthropic-dangerous-direct-browser-access: "true"

  # --- Static API Key ---
  - path: /twitter
    upstream: https://api.tweetapi.com
    upstream_auth:
      mode: static_api_key
      header: x-api-key
      value: ${TWITTER_API_KEY}

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
  # - path: /spotify
  #   upstream: https://api.spotify.com
  #   upstream_auth:
  #     mode: oauth_client_credentials
  #     client_id: ${SPOTIFY_CLIENT_ID}
  #     client_secret: ${SPOTIFY_CLIENT_SECRET}
  #     token_url: https://accounts.spotify.com/api/token
  #     scopes: [user-read-recently-played]
```

### Configuration Reference

#### `server`

| Field | Description | Default |
|---|---|---|
| `listen` | Address and port to listen on | `:4000` |
| `token_state_file` | Path to persist OAuth token state | *(none)* |

#### `routes[]`

| Field | Description | Required |
|---|---|---|
| `path` | URL path prefix to match (e.g., `/anthropic`) | Yes |
| `upstream` | Base URL of the upstream service | Yes |
| `inbound_auth` | Inbound request validation (see below) | No |
| `upstream_auth` | Upstream authentication config (see below) | Yes |
| `extra_headers` | Map of additional headers to add to upstream requests | No |

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

## How It Works

```
Client                    Switcheroo                   Upstream API
  |                           |                             |
  |  GET /twitter/v2/tweets   |                             |
  |-------------------------->|                             |
  |                           |  match route /twitter       |
  |                           |  add x-api-key header       |
  |                           |                             |
  |                           |  GET /v2/tweets             |
  |                           |  x-api-key: <real key>      |
  |                           |---------------------------->|
  |                           |                             |
  |                           |         200 OK              |
  |                           |<----------------------------|
  |        200 OK             |                             |
  |<--------------------------|                             |
```

1. Client sends a request to a switcheroo route (e.g., `/twitter/v2/tweets`)
2. Switcheroo matches the longest path prefix to find the route
3. If `inbound_auth` is configured, the request header is validated (401 on failure)
4. The route path prefix is stripped from the URL (`/twitter/v2/tweets` becomes `/v2/tweets`)
5. Upstream credentials are injected based on the auth mode
6. Extra headers are added
7. The request is forwarded to the upstream service
8. If the upstream returns 401 and the auth mode supports refresh, tokens are refreshed and the request is retried once
9. The response is proxied back to the client

## Using with OpenClaw

Point your [OpenClaw](https://github.com/openclaw/openclaw) gateway's API base URL at switcheroo instead of the upstream service directly. For example, configure OpenClaw to use `http://localhost:4000/anthropic` as the Anthropic API endpoint. OpenClaw sends requests without real credentials (or with a local shared secret), and switcheroo handles the rest.

This keeps production API keys out of the OpenClaw configuration and centralizes credential management in one place.

## License

See [LICENSE](LICENSE) for details.

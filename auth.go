package main

import (
	"net/http"
)

// AuthProvider injects upstream authentication into an outbound request.
type AuthProvider interface {
	ApplyAuth(req *http.Request) error
	// ForceRefresh attempts to refresh credentials. Returns true if refreshed.
	ForceRefresh() (bool, error)
}

// --- Static Bearer Token ---

type StaticBearerAuth struct {
	Token string
}

func (a *StaticBearerAuth) ApplyAuth(req *http.Request) error {
	req.Header.Set("Authorization", "Bearer "+a.Token)
	return nil
}

func (a *StaticBearerAuth) ForceRefresh() (bool, error) {
	return false, nil // static tokens can't be refreshed
}

// --- Static API Key ---

type StaticAPIKeyAuth struct {
	Header string
	Value  string
}

func (a *StaticAPIKeyAuth) ApplyAuth(req *http.Request) error {
	req.Header.Set(a.Header, a.Value)
	return nil
}

func (a *StaticAPIKeyAuth) ForceRefresh() (bool, error) {
	return false, nil
}

// --- OAuth Refresh Token ---

type OAuthRefreshAuth struct {
	state *TokenState
}

func NewOAuthRefreshAuth(routePath string, cfg UpstreamAuth, store *TokenStore) *OAuthRefreshAuth {
	state := store.GetOrCreate(routePath, cfg.TokenURL, cfg.ClientID, cfg.ClientSecret, cfg.AccessToken, cfg.RefreshToken, nil)
	return &OAuthRefreshAuth{state: state}
}

func (a *OAuthRefreshAuth) ApplyAuth(req *http.Request) error {
	token, err := a.state.GetAccessToken()
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

func (a *OAuthRefreshAuth) ForceRefresh() (bool, error) {
	return a.state.ForceRefresh()
}

// --- OAuth Client Credentials ---

type OAuthClientCredsAuth struct {
	state *TokenState
}

func NewOAuthClientCredsAuth(routePath string, cfg UpstreamAuth, store *TokenStore) *OAuthClientCredsAuth {
	state := store.GetOrCreate(routePath, cfg.TokenURL, cfg.ClientID, cfg.ClientSecret, "", "", cfg.Scopes)
	return &OAuthClientCredsAuth{state: state}
}

func (a *OAuthClientCredsAuth) ApplyAuth(req *http.Request) error {
	token, err := a.state.GetAccessToken()
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

func (a *OAuthClientCredsAuth) ForceRefresh() (bool, error) {
	return a.state.ForceRefresh()
}

// NewAuthProvider creates the appropriate AuthProvider for a route.
func NewAuthProvider(route Route, store *TokenStore) AuthProvider {
	switch route.UpstreamAuth.Mode {
	case "static_bearer":
		return &StaticBearerAuth{Token: route.UpstreamAuth.Token}
	case "static_api_key":
		return &StaticAPIKeyAuth{Header: route.UpstreamAuth.Header, Value: route.UpstreamAuth.Value}
	case "oauth_refresh_token":
		return NewOAuthRefreshAuth(route.Path, route.UpstreamAuth, store)
	case "oauth_client_credentials":
		return NewOAuthClientCredsAuth(route.Path, route.UpstreamAuth, store)
	default:
		return &StaticBearerAuth{} // unreachable after validation
	}
}

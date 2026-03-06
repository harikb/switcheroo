package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))

	configPath := flag.String("config", "switcheroo.yaml", "path to config file")
	register := flag.Bool("register", false, "register this proxy with the DeClaw gateway")
	pair := flag.Bool("pair", false, "initiate pairing with a DeClaw phone app")
	flag.Parse()

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	// Handle registration/pairing commands (exit after completion)
	if *register {
		runRegistration(cfg)
		return
	}
	if *pair {
		runPairing(cfg)
		return
	}

	slog.Info("loaded routes", "count", len(cfg.Routes), "mode", cfg.Server.Mode)
	for _, r := range cfg.Routes {
		slog.Info("route", "path", r.Path, "upstream", r.Upstream, "auth_mode", r.UpstreamAuth.Mode)
	}

	store := NewTokenStore(cfg.Server.TokenStateFile)

	// Create auth providers (this registers OAuth routes with the store)
	handler, err := NewProxyHandler(cfg, store)
	if err != nil {
		slog.Error("failed to create handler", "error", err)
		os.Exit(1)
	}

	// Initialize grant store
	if cfg.Server.GrantDB == "" {
		slog.Error("server.grant_db is required")
		os.Exit(1)
	}
	grantStore, err := NewSQLiteGrantStore(cfg.Server.GrantDB)
	if err != nil {
		slog.Error("failed to open grant db", "error", err)
		os.Exit(1)
	}
	slog.Info("grant store opened", "backend", "sqlite", "path", cfg.Server.GrantDB)

	// Load policy into grants and deny list
	denyList := NewDenyList(cfg.Policy.Deny)
	if len(cfg.Policy.Allow) > 0 {
		grants := ConvertPolicyRulesToGrants(cfg.Policy.Allow)
		for _, g := range grants {
			grantStore.Add(g)
		}
		slog.Info("loaded policy", "allow_grants", len(grants), "deny_rules", len(denyList.rules))
	}

	// Create forward proxy handler
	var forwardProxy *ForwardProxyHandler
	if cfg.ForwardProxy.Enabled {
		forwardProxy = NewForwardProxyHandler(cfg.ForwardProxy, grantStore, denyList)
		slog.Info("forward proxy enabled", "allowed_ports", cfg.ForwardProxy.AllowedPorts)
	}

	// Create grant request store (for pre-approval API)
	grantRequestStore := NewGrantRequestStore()

	// Load agent config if path is set
	var agentConfig *AgentConfig
	if cfg.Server.AgentConfigPath != "" {
		var err error
		agentConfig, err = LoadAgentConfig(cfg.Server.AgentConfigPath)
		if err != nil {
			slog.Error("failed to load agent config", "error", err)
			os.Exit(1)
		}
		slog.Info("loaded agent config", "path", cfg.Server.AgentConfigPath, "routes", len(agentConfig.Routes))
	}

	// Create management API
	mgmtAPI := NewManagementAPI(grantStore, denyList, cfg.Server.Mode, cfg.Policy)
	mgmtAPI.grantRequestStore = grantRequestStore
	mgmtAPI.mcpHandler = NewMCPHandler(mgmtAPI)
	mgmtAPI.agentConfig = agentConfig
	mgmtAPI.routes = cfg.Routes

	// Initialize DeClaw client if enabled and keys are present
	var declawClient *GatewayClient
	if cfg.DeClaw.Enabled && cfg.DeClaw.ProxyID != "" && cfg.DeClaw.ProxyAPIKey != "" {
		pendingStore := NewPendingRequestStore()
		declawClient = NewGatewayClient(cfg.DeClaw, pendingStore)

		// Load crypto keys if available
		if cfg.DeClaw.ProxyEncryptionKeyFile != "" {
			privKey, err := LoadX25519PrivateKey(cfg.DeClaw.ProxyEncryptionKeyFile)
			if err != nil {
				slog.Error("could not load proxy encryption key", "error", err)
				os.Exit(1)
			}
			declawClient.proxyPrivKey = privKey
		}

		if cfg.DeClaw.PhoneEncryptionKey != "" {
			pubKey, err := ParseX25519PublicKey(cfg.DeClaw.PhoneEncryptionKey)
			if err != nil {
				slog.Error("could not parse phone encryption key", "error", err)
				os.Exit(1)
			}
			declawClient.phoneEncryptionKey = pubKey
		}

		if cfg.DeClaw.PhoneSigningKey != "" {
			sigKey, err := ParseP256PublicKey(cfg.DeClaw.PhoneSigningKey)
			if err != nil {
				slog.Error("could not parse phone signing key", "error", err)
				os.Exit(1)
			}
			declawClient.phoneSigningKey = sigKey
		}

		// Start WebSocket connection in background
		go declawClient.ConnectWebSocket(context.Background())

		slog.Info("declaw connected", "gateway_url", cfg.DeClaw.GatewayURL, "proxy_id", cfg.DeClaw.ProxyID)
	} else if cfg.DeClaw.Enabled {
		slog.Info("declaw enabled but proxy_id/proxy_api_key not set, running in standalone mode")
	}

	// Parse management API allowed CIDRs
	mgmtAllowedNets, err := parseCIDRs(cfg.Server.ManagementAPIAllowedCIDRs)
	if err != nil {
		slog.Error("failed to parse management_api_allowed_cidrs", "error", err)
		os.Exit(1)
	}
	if len(mgmtAllowedNets) > 0 {
		slog.Info("management API allowed CIDRs", "cidrs", cfg.Server.ManagementAPIAllowedCIDRs)
	}

	// Wire everything into the proxy handler
	handler.mode = cfg.Server.Mode
	handler.grantStore = grantStore
	handler.denyList = denyList
	handler.forwardProxy = forwardProxy
	handler.mgmtAPI = mgmtAPI
	handler.declawClient = declawClient
	handler.mgmtAllowedNets = mgmtAllowedNets

	// Wire DeClaw into forward proxy and management API
	if forwardProxy != nil {
		forwardProxy.declawClient = declawClient
		forwardProxy.mgmtAPI = mgmtAPI
	}
	mgmtAPI.declawClient = declawClient

	// Build reload function shared by SIGHUP and POST /reload
	reloadFn := buildReloadFunc(*configPath, grantStore, handler, forwardProxy, mgmtAPI, agentConfig)
	mgmtAPI.onReload = reloadFn

	// Load persisted token state (after routes are registered)
	if err := store.Load(); err != nil {
		slog.Error("could not load token state", "error", err)
		os.Exit(1)
	}

	// SIGHUP handler for config hot-reload
	go handleSIGHUP(reloadFn)

	// File watcher for config hot-reload
	watchPaths := []string{*configPath}
	if cfg.Server.AgentConfigPath != "" {
		watchPaths = append(watchPaths, cfg.Server.AgentConfigPath)
	}
	go watchConfigFiles(watchPaths, reloadFn)

	slog.Info("listening", "addr", cfg.Server.Listen)
	if err := http.ListenAndServe(cfg.Server.Listen, handler); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}

// buildReloadFunc returns a function that reloads policy from the config file.
// On reload:
//  1. Re-parse config. If invalid, return error (keep old config).
//  2. Remove old policy grants from the grant store.
//  3. Convert new policy.allow rules to grants and add them.
//  4. Rebuild the deny list from policy.deny.
//  5. Update the deny list pointer on handler, forward proxy, and management API.
//  6. Update the policy on management API (for the /policy endpoint).
//
// DeClaw grants (in memory + DB) are NOT affected by reload.
func buildReloadFunc(configPath string, grantStore GrantStore, handler *ProxyHandler, forwardProxy *ForwardProxyHandler, mgmtAPI *ManagementAPI, agentConfig *AgentConfig) func() error {
	return func() error {
		newCfg, err := LoadConfig(configPath)
		if err != nil {
			return fmt.Errorf("parse config: %w", err)
		}

		// 1. Remove old policy grants
		grantStore.RemoveBySource("policy")

		// 2. Add new policy grants
		if len(newCfg.Policy.Allow) > 0 {
			grants := ConvertPolicyRulesToGrants(newCfg.Policy.Allow)
			for _, g := range grants {
				grantStore.Add(g)
			}
			slog.Info("reload: loaded allow grants from policy", "count", len(grants))
		}

		// 3. Rebuild deny list
		newDenyList := NewDenyList(newCfg.Policy.Deny)
		slog.Info("reload: loaded deny rules from policy", "count", len(newCfg.Policy.Deny))

		// 4. Swap deny list on all components
		handler.denyList = newDenyList
		if forwardProxy != nil {
			forwardProxy.denyList = newDenyList
		}
		mgmtAPI.denyList = newDenyList

		// 5. Update policy on management API
		mgmtAPI.policy = newCfg.Policy
		mgmtAPI.routes = newCfg.Routes

		// 6. Reload agent config if configured
		if agentConfig != nil {
			reloaded, err := LoadAgentConfig(agentConfig.path)
			if err != nil {
				slog.Error("reload: failed to reload agent config", "error", err)
			} else {
				agentConfig.mu.Lock()
				agentConfig.Routes = reloaded.Routes
				agentConfig.mu.Unlock()
				slog.Info("reload: loaded agent config routes", "count", len(reloaded.Routes))
			}
		}

		slog.Info("config reloaded successfully")
		return nil
	}
}

// watchConfigFiles watches config files for changes and triggers a reload.
// Uses fsnotify with a 500ms debounce to avoid reloading multiple times
// for rapid successive writes.
func watchConfigFiles(paths []string, reloadFn func() error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		slog.Error("failed to create file watcher", "error", err)
		return
	}
	defer watcher.Close()

	for _, path := range paths {
		if err := watcher.Add(path); err != nil {
			slog.Warn("failed to watch config file", "path", path, "error", err)
		} else {
			slog.Info("watching config file for changes", "path", path)
		}
	}

	var debounceTimer *time.Timer
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				if debounceTimer != nil {
					debounceTimer.Stop()
				}
				debounceTimer = time.AfterFunc(500*time.Millisecond, func() {
					slog.Info("config file changed, reloading", "path", event.Name)
					if err := reloadFn(); err != nil {
						slog.Error("config reload after file change failed", "error", err)
					}
				})
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			slog.Error("file watcher error", "error", err)
		}
	}
}

// handleSIGHUP listens for SIGHUP and triggers a config reload.
func handleSIGHUP(reloadFn func() error) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)

	for range sigCh {
		slog.Info("SIGHUP received, reloading config")
		if err := reloadFn(); err != nil {
			slog.Error("config reload failed, keeping old config", "error", err)
		}
	}
}

package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"dusheng-panel/apps/agent/internal/client"
	"dusheng-panel/apps/agent/internal/configsync"
	agentruntime "dusheng-panel/apps/agent/internal/runtime"
	"dusheng-panel/apps/agent/internal/supervisor"
)

const version = "dev"

func main() {
	logger := log.New(os.Stdout, "dusheng-agent ", log.LstdFlags|log.Lmicroseconds)

	baseURL := flag.String("base-url", firstEnv("DUSHENG_BASE_URL", "DUSHENG_API_URL", "BASE_URL"), "DuSheng Panel base URL")
	installToken := flag.String("install-token", firstEnv("DUSHENG_INSTALL_TOKEN", "INSTALL_TOKEN"), "one-time install token")
	nodeToken := flag.String("node-token", firstEnv("DUSHENG_NODE_TOKEN", "NODE_TOKEN"), "registered node token")
	dataDir := flag.String("data-dir", firstEnvDefault("data", "DUSHENG_DATA_DIR", "DATA_DIR"), "agent state directory")
	name := flag.String("name", firstEnvDefault("DuSheng Node", "DUSHENG_NODE_NAME", "DUSHENG_NAME", "NAME"), "node name used during registration")
	gostPath := flag.String("gost-path", firstEnv("DUSHENG_GOST_PATH", "DUSHENG_GOST_BIN", "GOST_PATH", "GOST_BIN"), "path to gost binary")
	flag.Parse()

	if strings.TrimSpace(*baseURL) == "" {
		logger.Fatal("base-url is required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	creds, found, err := client.LoadCredentials(*dataDir)
	if err != nil {
		logger.Fatalf("load credentials: %v", err)
	}
	if strings.TrimSpace(*nodeToken) != "" {
		creds.NodeToken = strings.TrimSpace(*nodeToken)
		found = true
	}

	api := client.New(*baseURL, creds.NodeToken)
	if !found || strings.TrimSpace(creds.NodeToken) == "" {
		if strings.TrimSpace(*installToken) == "" {
			logger.Fatal("install-token is required when node-token is not available")
		}
		logger.Printf("node token not found; registering node %q", *name)
		creds, err = api.Register(ctx, client.RegisterRequest{
			InstallToken: strings.TrimSpace(*installToken),
			Name:         strings.TrimSpace(*name),
			UUID:         creds.UUID,
			Version:      version,
		})
		if err != nil {
			logger.Fatalf("register node: %v", err)
		}
		if err := client.SaveCredentials(*dataDir, creds); err != nil {
			logger.Fatalf("save credentials: %v", err)
		}
		api.SetNodeToken(creds.NodeToken)
		logger.Printf("registered node id=%d uuid=%s", creds.NodeID, creds.UUID)
	}

	gost := supervisor.New(*gostPath, logger)
	rt := agentruntime.New(api, logger, agentruntime.Options{})
	syncer := configsync.New(api, *dataDir, rt, logger)

	if err := syncer.SyncOnce(ctx); err != nil {
		logger.Printf("initial config sync failed: %v", err)
	}
	if err := sendHeartbeat(ctx, api, syncer, gost, strings.TrimSpace(*gostPath), logger); err != nil {
		logger.Printf("initial heartbeat failed: %v", err)
	}

	configTicker := time.NewTicker(30 * time.Second)
	heartbeatTicker := time.NewTicker(30 * time.Second)
	defer configTicker.Stop()
	defer heartbeatTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := rt.Stop(shutdownCtx); err != nil {
				logger.Printf("stop runtime: %v", err)
			}
			if err := gost.Stop(shutdownCtx); err != nil {
				logger.Printf("stop gost: %v", err)
			}
			logger.Printf("agent stopped")
			return
		case <-configTicker.C:
			if err := syncer.SyncOnce(ctx); err != nil {
				logger.Printf("config sync failed: %v", err)
			}
		case <-heartbeatTicker.C:
			if err := sendHeartbeat(ctx, api, syncer, gost, strings.TrimSpace(*gostPath), logger); err != nil {
				logger.Printf("heartbeat failed: %v", err)
			}
		}
	}
}

func sendHeartbeat(ctx context.Context, api *client.Client, syncer *configsync.Syncer, gost *supervisor.Supervisor, gostPath string, logger *log.Logger) error {
	host, _ := os.Hostname()
	runtimeStatus := syncer.RuntimeStatus()
	resp, err := api.Heartbeat(ctx, client.HeartbeatRequest{
		Version:         version,
		AppliedRevision: syncer.AppliedRevision(),
		System: map[string]any{
			"hostname":          host,
			"os":                runtime.GOOS,
			"arch":              runtime.GOARCH,
			"goVersion":         runtime.Version(),
			"runtimeActive":     syncer.RuntimeActive(),
			"runtime":           runtimeStatus,
			"gostActive":        gost.Running(),
			"gostStatus":        gost.Status(),
			"gostPath":          gostPath,
			"trafficReporting":  "tcp_runtime",
			"protocolDetection": "tcp_runtime",
		},
	})
	if err != nil {
		return err
	}
	logger.Printf("heartbeat ok desiredRevision=%d", resp.DesiredRevision)
	return nil
}

func firstEnv(keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}

func firstEnvDefault(def string, keys ...string) string {
	if value := firstEnv(keys...); value != "" {
		return value
	}
	return def
}

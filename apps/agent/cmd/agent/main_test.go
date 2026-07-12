package main

import (
	"context"
	"io"
	"log"
	"testing"

	"dusheng-panel/apps/agent/internal/client"
	"dusheng-panel/apps/agent/internal/configsync"
	"dusheng-panel/apps/agent/internal/probe"
	agentruntime "dusheng-panel/apps/agent/internal/runtime"
	"github.com/prometheus/client_golang/prometheus"
)

func TestGostBinEnvCompatibility(t *testing.T) {
	t.Setenv("DUSHENG_GOST_BIN", "/usr/local/bin/gost")

	got := firstEnv("DUSHENG_GOST_PATH", "DUSHENG_GOST_BIN", "GOST_PATH", "GOST_BIN")
	if got != "/usr/local/bin/gost" {
		t.Fatalf("firstEnv() = %q, want DUSHENG_GOST_BIN value", got)
	}
}

func TestPresentEmptyMetricsEnvDisablesDefaultListener(t *testing.T) {
	t.Setenv("DUSHENG_METRICS_LISTEN", "")
	if got := firstPresentEnvDefault("127.0.0.1:19090", "DUSHENG_METRICS_LISTEN"); got != "" {
		t.Fatalf("firstPresentEnvDefault() = %q, want empty value to disable metrics", got)
	}
}

func TestAgentMetricsCollectorGathersRuntimeStatus(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	forwarding := agentruntime.New(nil, logger, agentruntime.Options{})
	probes := probe.New(nil, logger)
	runtimeManager := &combinedRuntime{forwarding: forwarding, probes: probes}
	syncer := configsync.New(client.New("http://127.0.0.1", "token"), t.TempDir(), runtimeManager, logger)
	registry := prometheus.NewRegistry()
	registry.MustRegister(newAgentCollector(runtimeManager, syncer))
	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}
	if len(families) == 0 {
		t.Fatal("Gather() returned no metric families")
	}
	if err := runtimeManager.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

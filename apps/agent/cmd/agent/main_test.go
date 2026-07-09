package main

import "testing"

func TestGostBinEnvCompatibility(t *testing.T) {
	t.Setenv("DUSHENG_GOST_BIN", "/usr/local/bin/gost")

	got := firstEnv("DUSHENG_GOST_PATH", "DUSHENG_GOST_BIN", "GOST_PATH", "GOST_BIN")
	if got != "/usr/local/bin/gost" {
		t.Fatalf("firstEnv() = %q, want DUSHENG_GOST_BIN value", got)
	}
}

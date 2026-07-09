package supervisor

import (
	"path/filepath"
	"testing"
)

func TestStatusReportsNotConfigured(t *testing.T) {
	s := New("", nil)
	if got := s.Status(); got != "not_configured" {
		t.Fatalf("Status() = %q, want not_configured", got)
	}
}

func TestStatusReportsMissingGost(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "missing-gost"), nil)
	if got := s.Status(); got != "missing" {
		t.Fatalf("Status() = %q, want missing", got)
	}
}

package internal

import (
	"strings"
	"testing"
)

func TestNewDefaultConfigTrimsEmbeddedSDKVersion(t *testing.T) {
	cfg := NewDefaultConfig()

	if cfg.SDKVersion == "" {
		t.Fatal("SDKVersion is empty")
	}
	if strings.TrimSpace(cfg.SDKVersion) != cfg.SDKVersion {
		t.Fatalf("SDKVersion contains surrounding whitespace: %q", cfg.SDKVersion)
	}
}

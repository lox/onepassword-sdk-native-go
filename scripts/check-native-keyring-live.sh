#!/usr/bin/env sh
set -eu

if [ -z "${OP_SERVICE_ACCOUNT_TOKEN:-}" ] || [ -z "${KEYRING_1PASSWORD_VAULT:-}" ]; then
	printf '%s\n' "skipping live native keyring check: OP_SERVICE_ACCOUNT_TOKEN and KEYRING_1PASSWORD_VAULT are required"
	exit 0
fi

provider_dir="${KEYRING_1PASSWORD_DIR:-/Users/lachlan/Develop/keyring-1password}"
if [ ! -d "$provider_dir" ]; then
	printf '%s\n' "keyring provider checkout not found: $provider_dir" >&2
	exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cp -R "$provider_dir/." "$tmp"
cd "$tmp"

old_imports="$(grep -rl 'github.com/1password/onepassword-sdk-go' . || true)"
if [ -n "$old_imports" ]; then
	perl -pi -e 's#github\.com/1password/onepassword-sdk-go#github.com/lox/onepassword-sdk-native-go#g' $old_imports
fi
go mod edit -require github.com/lox/onepassword-sdk-native-go@v0.0.0
go mod edit -replace github.com/lox/onepassword-sdk-native-go="$OLDPWD"
go mod tidy

if grep -E 'extism|wazero|observe|protobuf|wabin|otlp' go.mod go.sum >/dev/null; then
	printf '%s\n' "provider go.mod/go.sum unexpectedly retain wasm-era modules" >&2
	grep -E 'extism|wazero|observe|protobuf|wabin|otlp' go.mod go.sum >&2
	exit 1
fi

deps="$(go list -deps ./...)"
if printf '%s\n' "$deps" | grep -E 'extism|wazero|internal/wasm' >/dev/null; then
	printf '%s\n' "provider package graph unexpectedly depends on wasm runtime" >&2
	printf '%s\n' "$deps" | grep -E 'extism|wazero|internal/wasm' >&2
	exit 1
fi

modules="$(go list -m all)"
if printf '%s\n' "$modules" | grep -E 'extism|wazero|observe|protobuf|wabin|otlp' >/dev/null; then
	printf '%s\n' "provider module graph unexpectedly contains wasm-era modules" >&2
	printf '%s\n' "$modules" | grep -E 'extism|wazero|observe|protobuf|wabin|otlp' >&2
	exit 1
fi

cat >native_live_smoke_test.go <<'GO'
package onepassword

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/lox/keyring/v2"
)

func TestNativeLiveRoundTrip(t *testing.T) {
	ctx := context.Background()
	service := "native-sdk-smoke-" + time.Now().UTC().Format("20060102150405")
	key := "roundtrip"
	want := []byte("native-keyring-value")

	ring, err := keyring.Open(ctx,
		keyring.WithServiceName(service),
		keyring.WithProvider(Provider(
			Auth(AuthServiceAccount),
			ItemTitle(service),
			Timeout(30*time.Second),
		)),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = ring.Remove(context.Background(), key)
	}()

	if err := ring.Set(ctx, keyring.Item{Key: key, Data: want, Label: "native", Description: "smoke"}); err != nil {
		t.Fatalf("set: %v", err)
	}

	got, err := ring.Get(ctx, key)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !bytes.Equal(got.Data, want) || got.Label != "native" || got.Description != "smoke" {
		t.Fatalf("unexpected item: %+v", got)
	}

	keys, err := ring.Keys(ctx)
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	if len(keys) != 1 || keys[0] != key {
		t.Fatalf("unexpected keys: %v", keys)
	}

	if metadataReader, ok := ring.(keyring.MetadataReader); ok {
		metadata, err := metadataReader.Metadata(ctx, key)
		if err != nil {
			t.Fatalf("metadata: %v", err)
		}
		if metadata.Item == nil || metadata.Item.Key != key || len(metadata.Item.Data) != 0 {
			t.Fatalf("unexpected metadata: %+v", metadata)
		}
	}

	if err := ring.Remove(ctx, key); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := ring.Get(ctx, key); err == nil {
		t.Fatal("expected removed key to be missing")
	}
}
GO

go test -c -o "$tmp/provider-live.test" .
if strings "$tmp/provider-live.test" | grep -E 'github.com/extism|github.com/tetratelabs/wazero|internal/wasm/core.wasm' >/dev/null; then
	printf '%s\n' "provider live test binary unexpectedly contains wasm runtime symbols" >&2
	strings "$tmp/provider-live.test" | grep -E 'github.com/extism|github.com/tetratelabs/wazero|internal/wasm/core.wasm' >&2
	exit 1
fi

go test -run TestNativeLiveRoundTrip -count=1 .

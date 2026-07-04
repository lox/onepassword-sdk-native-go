#!/usr/bin/env sh
set -eu

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

go run ./example/native_secrets >/dev/null
go build -o "$tmp/native_secrets" ./example/native_secrets
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$tmp/native_secrets-linux" ./example/native_secrets
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o "$tmp/native_secrets-windows.exe" ./example/native_secrets

deps="$(go list -deps ./example/native_secrets)"
if printf '%s\n' "$deps" | grep -E 'extism|wazero|internal/wasm' >/dev/null; then
	printf '%s\n' "small CLI package graph unexpectedly depends on wasm runtime" >&2
	printf '%s\n' "$deps" | grep -E 'extism|wazero|internal/wasm' >&2
	exit 1
fi

if strings "$tmp/native_secrets" | grep -E 'github.com/extism|github.com/tetratelabs/wazero|internal/wasm/core.wasm' >/dev/null; then
	printf '%s\n' "small CLI binary unexpectedly contains wasm runtime symbols" >&2
	strings "$tmp/native_secrets" | grep -E 'github.com/extism|github.com/tetratelabs/wazero|internal/wasm/core.wasm' >&2
	exit 1
fi
if strings "$tmp/native_secrets-linux" "$tmp/native_secrets-windows.exe" | grep -E 'github.com/extism|github.com/tetratelabs/wazero|internal/wasm/core.wasm' >/dev/null; then
	printf '%s\n' "cross-compiled small CLI binaries unexpectedly contain wasm runtime symbols" >&2
	strings "$tmp/native_secrets-linux" "$tmp/native_secrets-windows.exe" | grep -E 'github.com/extism|github.com/tetratelabs/wazero|internal/wasm/core.wasm' >&2
	exit 1
fi

printf '%s\n' "small CLI has no extism/wazero/internal/wasm package deps or binary symbols and cross-compiles without CGO"

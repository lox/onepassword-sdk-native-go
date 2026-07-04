#!/usr/bin/env sh
set -eu

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

repo_dir="$(pwd)"
if [ -e "$repo_dir/internal/wasm/core.wasm" ]; then
	printf '%s\n' "embedded WASM payload still exists: internal/wasm/core.wasm" >&2
	exit 1
fi
if grep -E 'extism|wazero|observe|protobuf|wabin|otlp' "$repo_dir/go.mod" "$repo_dir/go.sum" >/dev/null; then
	printf '%s\n' "go.mod/go.sum still include wasm-era modules" >&2
	grep -E 'extism|wazero|observe|protobuf|wabin|otlp' "$repo_dir/go.mod" "$repo_dir/go.sum" >&2
	exit 1
fi

cd "$tmp"
go mod init example.com/native-module-audit >/dev/null
go mod edit -require github.com/lox/onepassword-sdk-native-go@v0.0.0
go mod edit -replace github.com/lox/onepassword-sdk-native-go="$repo_dir"
cat >main.go <<'GO'
package main

import onepassword "github.com/lox/onepassword-sdk-native-go"

func main() { _ = onepassword.Secrets }
GO

heavy="$(go list -m all | grep -E 'extism|wazero|observe|protobuf|wabin|otlp' || true)"
if [ -n "$heavy" ]; then
	printf '%s\n' "native module graph still includes wasm-era modules:"
	printf '%s\n' "$heavy"
	exit 0
fi

printf '%s\n' "native module graph has no wasm-era modules or embedded WASM payload"

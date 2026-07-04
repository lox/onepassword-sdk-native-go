#!/usr/bin/env sh
set -eu

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
go test ./...

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

go test -c -o "$tmp/provider.test" .
if strings "$tmp/provider.test" | grep -E 'github.com/extism|github.com/tetratelabs/wazero|internal/wasm/core.wasm' >/dev/null; then
	printf '%s\n' "provider test binary unexpectedly contains wasm runtime symbols" >&2
	strings "$tmp/provider.test" | grep -E 'github.com/extism|github.com/tetratelabs/wazero|internal/wasm/core.wasm' >&2
	exit 1
fi
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o "$tmp/provider-linux.test" .
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go test -c -o "$tmp/provider-windows.test.exe" .
if strings "$tmp/provider-linux.test" "$tmp/provider-windows.test.exe" | grep -E 'github.com/extism|github.com/tetratelabs/wazero|internal/wasm/core.wasm' >/dev/null; then
	printf '%s\n' "cross-compiled provider test binaries unexpectedly contain wasm runtime symbols" >&2
	strings "$tmp/provider-linux.test" "$tmp/provider-windows.test.exe" | grep -E 'github.com/extism|github.com/tetratelabs/wazero|internal/wasm/core.wasm' >&2
	exit 1
fi

printf '%s\n' "provider default build has no wasm-era module deps, package deps, or binary symbols and cross-compiles without CGO"

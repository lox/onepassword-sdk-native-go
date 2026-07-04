# Unofficial Native 1Password Go SDK

This is an unofficial native Go SDK for a small 1Password integration surface. It is not published or supported by 1Password.

The package name is `onepassword` and the module path is:

```bash
go get github.com/lox/onepassword-sdk-native-go
```

Use of 1Password APIs and services is governed by the [1Password API Terms of Service](https://1password.com/legal/api-sdk-terms-of-service).

## Binary Size

Measured on `darwin/arm64` with Go `1.24.0`, using stripped builds:

```bash
go build -trimpath -ldflags="-s -w"
```

| Program | Official SDK `v0.4.0` | This SDK | Difference |
| --- | ---: | ---: | ---: |
| Secret reference validation plus PIN/random password generation | 20.0 MB | 3.2 MB | 84.0% smaller |
| Service-account client plus `Secrets.Resolve` | 20.1 MB | 5.8 MB | 70.9% smaller |

The official SDK build pulled in 10 WASM-era modules matching `extism`, `wazero`, `observe`, `protobuf`, `wabin`, or `otlp`. This SDK pulled in none for the same programs.

## Service Accounts

Service-account clients use a native Go implementation. They do not embed or link the old WASM runtime.

```go
package main

import (
	"context"
	"os"

	"github.com/lox/onepassword-sdk-native-go"
)

func main() {
	client, err := onepassword.NewClient(
		context.Background(),
		onepassword.WithServiceAccountToken(os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")),
		onepassword.WithIntegrationInfo("My Integration", "v1.0.0"),
	)
	if err != nil {
		panic(err)
	}

	secret, err := client.Secrets().Resolve(context.Background(), "op://vault/item/field")
	if err != nil {
		panic(err)
	}
	_ = secret
}
```

## Native Service-Account Support

Unsupported service-account methods fail closed with a native SDK error instead of falling back to WASM.

| Area | Implemented | Not implemented |
| --- | --- | --- |
| Utilities | `Secrets.ValidateSecretReference`; `Secrets.GeneratePassword` for PIN and random recipes | Memorable password recipes |
| Secrets | `Secrets.Resolve`; `Secrets.ResolveAll`; default field resolution; `attribute=totp` | Other secret reference attributes |
| Vaults | `Vaults.List`; `Vaults.GetOverview`; `Vaults.Get` without optional params | Vault create, update, delete, group permission changes, and optional list/get params |
| Items | `Items.List`; `Items.Get`; `Items.GetAll`; `Items.Create`; `Items.CreateAll`; `Items.Put`; `Items.Delete`; `Items.DeleteAll` | `Items.Archive`, item sharing, file fields, and document item operations |
| Item filters | No filter; generated `ByState` active/archive filter | Other filters |
| Groups | None | `Groups.Get` |

## Desktop App

Desktop app authentication still uses the 1Password desktop shared library through CGO. Method support follows the installed desktop integration.

```go
client, err := onepassword.NewClient(
	context.Background(),
	onepassword.WithDesktopAppIntegration("account-name"),
	onepassword.WithIntegrationInfo("My Integration", "v1.0.0"),
)
```

## Examples

- `example/native_secrets` demonstrates native utilities that do not need a token.
- `example/desktop_app` demonstrates desktop app authentication.

## Validation

```bash
mise install
mise run check
```

`check-native-keyring-live` skips unless `OP_SERVICE_ACCOUNT_TOKEN` and `KEYRING_1PASSWORD_VAULT` are set.

package onepassword

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestNewClientNativeInitializesWithSAToken(t *testing.T) {
	if _, err := NewClient(context.Background(), WithServiceAccountToken(nativeClientTestServiceAccountToken(t))); err != nil {
		t.Fatal(err)
	}
}

func TestNativeKeyringItemMethodsValidateThroughPublicAPI(t *testing.T) {
	client, err := NewClient(context.Background(), WithServiceAccountToken(nativeClientTestServiceAccountToken(t)))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		call func(context.Context) error
		want string
	}{
		{
			name: "list by active state",
			call: func(ctx context.Context) error {
				_, err := client.Items().List(ctx, "vault", NewItemListFilterTypeVariantByState(&ItemListFilterByStateInner{
					Active: true,
				}))
				return err
			},
			want: `parameter "vault_id" must be a 26-character 1Password ID`,
		},
		{
			name: "get",
			call: func(ctx context.Context) error {
				_, err := client.Items().Get(ctx, "vault", "abcdefghijklmnopqrstuvwx34")
				return err
			},
			want: `parameter "vault_id" must be a 26-character 1Password ID`,
		},
		{
			name: "create",
			call: func(ctx context.Context) error {
				_, err := client.Items().Create(ctx, ItemCreateParams{VaultID: "vault"})
				return err
			},
			want: `parameter "vaultId" must be a 26-character 1Password ID`,
		},
		{
			name: "put",
			call: func(ctx context.Context) error {
				_, err := client.Items().Put(ctx, Item{ID: "item", VaultID: "abcdefghijklmnopqrstuvwx12"})
				return err
			},
			want: `parameter "id" must be a 26-character 1Password ID`,
		},
		{
			name: "delete",
			call: func(ctx context.Context) error {
				return client.Items().Delete(ctx, "vault", "item")
			},
			want: `parameter "vault_id" must be a 26-character 1Password ID`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call(context.Background())
			if err == nil {
				t.Fatal("expected validation error")
			}
			if got := err.Error(); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNativeSecretMethodsValidateThroughPublicAPI(t *testing.T) {
	client, err := NewClient(context.Background(), WithServiceAccountToken(nativeClientTestServiceAccountToken(t)))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		call func(context.Context) error
		want string
	}{
		{
			name: "resolve",
			call: func(ctx context.Context) error {
				_, err := client.Secrets().Resolve(ctx, "vault/item/field")
				return err
			},
			want: `secret reference is not prefixed with "op://"`,
		},
		{
			name: "resolve all",
			call: func(ctx context.Context) error {
				_, err := client.Secrets().ResolveAll(ctx, []string{"op://vault/item/field", "vault/item/field"})
				return err
			},
			want: `secret_references[1]: secret reference is not prefixed with "op://"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call(context.Background())
			if err == nil {
				t.Fatal("expected validation error")
			}
			if got := err.Error(); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func nativeClientTestServiceAccountToken(t *testing.T) string {
	t.Helper()
	payload, err := json.Marshal(struct {
		SignInAddress string            `json:"signInAddress"`
		Email         string            `json:"email"`
		SecretKey     string            `json:"secretKey"`
		SRPX          string            `json:"srpX"`
		MUK           nativeClientJWK   `json:"muk"`
		UserAuth      nativeClientAuth  `json:"userAuth"`
		DeviceUUID    string            `json:"deviceUuid"`
		Throttle      nativeClientToken `json:"throttleSecret"`
	}{
		SignInAddress: "example.1password.com:4000",
		Email:         "service@example.com",
		SecretKey:     "A3-C4ZJMN-PQTZTL-HGL84-G64M7-KVZRN-4ZVP6",
		SRPX:          strings.Repeat("1", 64),
		MUK: nativeClientJWK{
			Alg:    "A256GCM",
			Ext:    true,
			K:      base64.RawURLEncoding.EncodeToString([]byte("12345678901234567890123456789012")),
			KeyOps: []string{"encrypt", "decrypt"},
			Kty:    "oct",
			KID:    "mp",
		},
		UserAuth: nativeClientAuth{
			Alg:        "PBES2g-HS256",
			Iterations: 100000,
			Method:     "SRPg-4096",
			Salt:       base64.RawURLEncoding.EncodeToString([]byte("salt")),
		},
		DeviceUUID: "abcdefghijklmnopqrstuvwx12",
		Throttle:   nativeClientToken{Seed: strings.Repeat("a", 64), UUID: "abcdefghijklmnopqrstuvwx34"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return "ops_" + base64.RawURLEncoding.EncodeToString(payload)
}

type nativeClientJWK struct {
	Alg    string   `json:"alg"`
	Ext    bool     `json:"ext"`
	K      string   `json:"k"`
	KeyOps []string `json:"key_ops"`
	Kty    string   `json:"kty"`
	KID    string   `json:"kid"`
}

type nativeClientAuth struct {
	Alg        string `json:"alg"`
	Iterations uint32 `json:"iterations"`
	Method     string `json:"method"`
	Salt       string `json:"salt"`
}

type nativeClientToken struct {
	Seed string `json:"seed"`
	UUID string `json:"uuid"`
}

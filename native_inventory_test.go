package onepassword

import (
	"context"
	"testing"
)

func TestNativeInventoryAPIMethodsReachAuthBoundary(t *testing.T) {
	testNativeInventoryAPIMethodsReachAuthBoundary(t)
}

func testNativeInventoryAPIMethodsReachAuthBoundary(t *testing.T) {
	t.Helper()

	client, err := NewClient(context.Background(), WithServiceAccountToken(nativeClientTestServiceAccountToken(t)))
	if err != nil {
		t.Fatal(err)
	}

	vaultID := "abcdefghijklmnopqrstuvwx12"
	itemID := "abcdefghijklmnopqrstuvwx34"
	groupID := "abcdefghijklmnopqrstuvwx56"
	yes := true

	tests := []struct {
		name string
		call func(context.Context) error
		want string
	}{
		{
			name: "archive item",
			call: func(ctx context.Context) error {
				return client.Items().Archive(ctx, vaultID, itemID)
			},
			want: `native core cannot run "ItemsArchive" until its service-account route is implemented`,
		},
		{
			name: "list vaults",
			call: func(ctx context.Context) error {
				_, err := client.Vaults().List(ctx, VaultListParams{DecryptDetails: &yes})
				return err
			},
			want: `native core cannot run "VaultsList" until its service-account route is implemented`,
		},
		{
			name: "get vault",
			call: func(ctx context.Context) error {
				_, err := client.Vaults().Get(ctx, vaultID, VaultGetParams{Accessors: &yes})
				return err
			},
			want: `native core cannot run "VaultsGet" until its service-account route is implemented`,
		},
		{
			name: "get group",
			call: func(ctx context.Context) error {
				_, err := client.Groups().Get(ctx, groupID, GroupGetParams{VaultPermissions: &yes})
				return err
			},
			want: `native core cannot run "GroupsGet" until its service-account route is implemented`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call(context.Background())
			if err == nil {
				t.Fatal("expected native auth boundary error")
			}
			if got := err.Error(); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNativeUnsupportedPublicAPIMethodsFailClosed(t *testing.T) {
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
			name: "attach file",
			call: func(ctx context.Context) error {
				_, err := client.Items().Files().Attach(ctx, Item{}, FileCreateParams{})
				return err
			},
			want: `native core does not implement "ItemsFilesAttach"`,
		},
		{
			name: "read file",
			call: func(ctx context.Context) error {
				_, err := client.Items().Files().Read(ctx, "vault", "item", FileAttributes{})
				return err
			},
			want: `native core does not implement "ItemsFilesRead"`,
		},
		{
			name: "share policy",
			call: func(ctx context.Context) error {
				_, err := client.Items().Shares().GetAccountPolicy(ctx, "vault", "item")
				return err
			},
			want: `native core does not implement "ItemsSharesGetAccountPolicy"`,
		},
		{
			name: "share create",
			call: func(ctx context.Context) error {
				_, err := client.Items().Shares().Create(ctx, Item{}, ItemShareAccountPolicy{}, ItemShareParams{})
				return err
			},
			want: `native core does not implement "ItemsSharesCreate"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call(context.Background())
			if err == nil {
				t.Fatal("expected unsupported native method error")
			}
			if got := err.Error(); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

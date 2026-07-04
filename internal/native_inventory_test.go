package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestNativeVaultsListRequestPreservesParams(t *testing.T) {
	request, err := nativeVaultsListRequest(map[string]interface{}{
		"params": map[string]interface{}{"decryptDetails": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(request.Params, []byte(`"decryptDetails":true`)) {
		t.Fatalf("list params were not preserved: %s", request.Params)
	}
}

func TestNativeListVaultsUsesAccountRoute(t *testing.T) {
	sessionKey := []byte("12345678901234567890123456789012")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.URL.String(), "/api/v1/vaults"; got != want {
			t.Fatalf("got path %q, want %q", got, want)
		}
		response, err := nativeSealSessionPayload("session-id", sessionKey, []byte("123456789012"), []byte(`[{
			"id":"abcdefghijklmnopqrstuvwx12",
			"title":"Private",
			"vaultType":"userCreated"
		}]`))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Fatal(err)
		}
	}))
	defer server.Close()

	baseURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &nativeClient{
		baseURL:    baseURL,
		httpClient: server.Client(),
		session:    &nativeSession{ID: "session-id", Key: sessionKey},
	}
	response, err := client.listVaults(context.Background(), nativeVaultsListParams{})
	if err != nil {
		t.Fatal(err)
	}
	var got []map[string]interface{}
	if err := json.Unmarshal(response, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0]["title"] != "Private" {
		t.Fatalf("unexpected vaults response: %+v", got)
	}
}

func TestNativeListVaultsWithParamsStaysAtAuthBoundary(t *testing.T) {
	client := &nativeClient{session: &nativeSession{ID: "session-id", Key: []byte("12345678901234567890123456789012")}}
	_, err := client.listVaults(context.Background(), nativeVaultsListParams{Params: json.RawMessage(`{"decryptDetails":true}`)})
	if err == nil {
		t.Fatal("expected auth boundary error")
	}
	if got, want := err.Error(), `{"name":"NativeMethodNotImplemented","message":"native core cannot run \"VaultsList\" until its service-account route is implemented"}`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNativeGetVaultOverviewUsesVaultList(t *testing.T) {
	sessionKey := []byte("12345678901234567890123456789012")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.URL.String(), "/api/v1/vaults"; got != want {
			t.Fatalf("got path %q, want %q", got, want)
		}
		response, err := nativeSealSessionPayload("session-id", sessionKey, []byte("123456789012"), []byte(`[
			{"id":"abcdefghijklmnopqrstuvwx12","title":"Private","vaultType":"userCreated"},
			{"id":"abcdefghijklmnopqrstuvwx34","title":"Other","vaultType":"userCreated"}
		]`))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Fatal(err)
		}
	}))
	defer server.Close()

	baseURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &nativeClient{
		baseURL:    baseURL,
		httpClient: server.Client(),
		session:    &nativeSession{ID: "session-id", Key: sessionKey},
	}
	response, err := client.getVaultOverview(context.Background(), nativeVaultParams{VaultID: "abcdefghijklmnopqrstuvwx12"})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(response, &got); err != nil {
		t.Fatal(err)
	}
	if got["title"] != "Private" {
		t.Fatalf("unexpected overview: %+v", got)
	}

	_, err = client.getVaultOverview(context.Background(), nativeVaultParams{VaultID: "abcdefghijklmnopqrstuvwx56"})
	if err == nil {
		t.Fatal("expected not found")
	}
	if got, want := err.Error(), `{"name":"NotFound","message":"resource not found"}`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNativeVaultContentVersionUsesVaultList(t *testing.T) {
	sessionKey := []byte("12345678901234567890123456789012")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response, err := nativeSealSessionPayload("session-id", sessionKey, []byte("123456789012"), []byte(`[
			{"id":"abcdefghijklmnopqrstuvwx12","title":"Private","contentVersion":42},
			{"id":"abcdefghijklmnopqrstuvwx34","title":"Other","contentVersion":7}
		]`))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Fatal(err)
		}
	}))
	defer server.Close()

	client := nativeHTTPTestClient(t, server, sessionKey)
	version, err := client.vaultContentVersion(context.Background(), "abcdefghijklmnopqrstuvwx12")
	if err != nil {
		t.Fatal(err)
	}
	if version != 42 {
		t.Fatalf("got content version %d, want 42", version)
	}
}

func TestNativeVaultContentVersionRequiresMetadata(t *testing.T) {
	sessionKey := []byte("12345678901234567890123456789012")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response, err := nativeSealSessionPayload("session-id", sessionKey, []byte("123456789012"), []byte(`[
			{"id":"abcdefghijklmnopqrstuvwx12","title":"Private"}
		]`))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Fatal(err)
		}
	}))
	defer server.Close()

	client := nativeHTTPTestClient(t, server, sessionKey)
	_, err := client.vaultContentVersion(context.Background(), "abcdefghijklmnopqrstuvwx12")
	if err == nil {
		t.Fatal("expected missing content version error")
	}
	if got, want := err.Error(), `{"name":"Internal","message":"vault metadata is missing contentVersion"}`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNativeGetVaultWithoutParamsUsesVaultList(t *testing.T) {
	sessionKey := []byte("12345678901234567890123456789012")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response, err := nativeSealSessionPayload("session-id", sessionKey, []byte("123456789012"), []byte(`[
			{"id":"abcdefghijklmnopqrstuvwx12","title":"Private","vaultType":"userCreated"}
		]`))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Fatal(err)
		}
	}))
	defer server.Close()

	baseURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &nativeClient{
		baseURL:    baseURL,
		httpClient: server.Client(),
		session:    &nativeSession{ID: "session-id", Key: sessionKey},
	}
	response, err := client.getVault(context.Background(), nativeVaultGetParams{VaultID: "abcdefghijklmnopqrstuvwx12"})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(response, &got); err != nil {
		t.Fatal(err)
	}
	if got["id"] != "abcdefghijklmnopqrstuvwx12" {
		t.Fatalf("unexpected vault: %+v", got)
	}
}

func TestNativeGetVaultWithParamsStaysAtAuthBoundary(t *testing.T) {
	client := &nativeClient{session: &nativeSession{ID: "session-id", Key: []byte("12345678901234567890123456789012")}}
	_, err := client.getVault(context.Background(), nativeVaultGetParams{
		VaultID:     "abcdefghijklmnopqrstuvwx12",
		VaultParams: json.RawMessage(`{"accessors":true}`),
	})
	if err == nil {
		t.Fatal("expected auth boundary error")
	}
	if got, want := err.Error(), `{"name":"NativeMethodNotImplemented","message":"native core cannot run \"VaultsGet\" until its service-account route is implemented"}`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNativeVaultGetRequestValidatesVaultID(t *testing.T) {
	request, err := nativeVaultGetRequest(map[string]interface{}{
		"vault_id":     "abcdefghijklmnopqrstuvwx12",
		"vault_params": map[string]interface{}{"accessors": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if request.VaultID != "abcdefghijklmnopqrstuvwx12" {
		t.Fatalf("got vault id %q", request.VaultID)
	}
	if !bytes.Contains(request.VaultParams, []byte(`"accessors":true`)) {
		t.Fatalf("vault params were not preserved: %s", request.VaultParams)
	}

	_, err = nativeVaultGetRequest(map[string]interface{}{"vault_id": "vault"})
	if err == nil {
		t.Fatal("expected bad vault id error")
	}
	if got, want := err.Error(), `parameter "vault_id" must be a 26-character 1Password ID`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNativeGroupGetRequestValidatesGroupID(t *testing.T) {
	request, err := nativeGroupGetRequest(map[string]interface{}{
		"group_id":     "abcdefghijklmnopqrstuvwx12",
		"group_params": map[string]interface{}{"vaultPermissions": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if request.GroupID != "abcdefghijklmnopqrstuvwx12" {
		t.Fatalf("got group id %q", request.GroupID)
	}
	if !bytes.Contains(request.GroupParams, []byte(`"vaultPermissions":true`)) {
		t.Fatalf("group params were not preserved: %s", request.GroupParams)
	}

	_, err = nativeGroupGetRequest(map[string]interface{}{"group_id": "group"})
	if err == nil {
		t.Fatal("expected bad group id error")
	}
	if got, want := err.Error(), `parameter "group_id" must be a 26-character 1Password ID`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

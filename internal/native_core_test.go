package internal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNativeCoreUnsupportedMethod(t *testing.T) {
	core := GetNativeCore()
	config := NewDefaultConfig()
	config.SAToken = testServiceAccountToken(t)

	id, err := core.InitClient(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	_, err = core.Invoke(context.Background(), InvokeConfig{
		Invocation: Invocation{
			ClientID: id,
			Parameters: Parameters{
				MethodName: "NotImplemented",
			},
		},
	})
	if err == nil {
		t.Fatal("expected unsupported method error")
	}
	if got, want := err.Error(), `{"name":"UnsupportedNativeMethod","message":"native core does not implement \"NotImplemented\""}`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNativeCoreSecretMethodsValidateParams(t *testing.T) {
	core := GetNativeCore()

	tests := []struct {
		name   string
		method string
		params map[string]interface{}
		want   string
	}{
		{
			name:   "resolve missing reference",
			method: "SecretsResolve",
			params: map[string]interface{}{},
			want:   `{"name":"InvalidUserInput","message":"missing parameter \"secret_reference\""}`,
		},
		{
			name:   "resolve bad reference",
			method: "SecretsResolve",
			params: map[string]interface{}{"secret_reference": "vault/item/field"},
			want:   `{"name":"InvalidUserInput","message":"secret reference is not prefixed with \"op://\""}`,
		},
		{
			name:   "resolve all bad reference",
			method: "SecretsResolveAll",
			params: map[string]interface{}{"secret_references": []interface{}{"op://vault/item/field", "vault/item/field"}},
			want:   `{"name":"InvalidUserInput","message":"secret_references[1]: secret reference is not prefixed with \"op://\""}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := core.InnerCore.Invoke(context.Background(), mustMarshal(t, InvokeConfig{
				Invocation: Invocation{
					Parameters: Parameters{
						MethodName:       tt.method,
						SerializedParams: tt.params,
					},
				},
			}))
			if err == nil {
				t.Fatal("expected validation error")
			}
			if got := err.Error(); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNativeCoreValidateSecretReference(t *testing.T) {
	core := GetNativeCore()

	_, err := core.InnerCore.Invoke(context.Background(), mustMarshal(t, InvokeConfig{
		Invocation: Invocation{
			Parameters: Parameters{
				MethodName:       "ValidateSecretReference",
				SerializedParams: map[string]interface{}{"secret_reference": "op://vault/item/field"},
			},
		},
	}))
	if err != nil {
		t.Fatal(err)
	}
}

func TestNativeCoreValidateSecretReferenceRejectsUnsupportedQuery(t *testing.T) {
	core := GetNativeCore()

	_, err := core.InnerCore.Invoke(context.Background(), mustMarshal(t, InvokeConfig{
		Invocation: Invocation{
			Parameters: Parameters{
				MethodName:       "ValidateSecretReference",
				SerializedParams: map[string]interface{}{"secret_reference": "op://vault/item/field?unknown=value"},
			},
		},
	}))
	if err == nil {
		t.Fatal("expected validation error")
	}
	if got, want := err.Error(), `{"name":"Validation","message":"only the attribute query parameter is supported"}`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNativeCoreGeneratePINPassword(t *testing.T) {
	core := GetNativeCore()

	response, err := core.InnerCore.Invoke(context.Background(), mustMarshal(t, InvokeConfig{
		Invocation: Invocation{
			Parameters: Parameters{
				MethodName: "GeneratePassword",
				SerializedParams: map[string]interface{}{
					"recipe": map[string]interface{}{
						"type":       "Pin",
						"parameters": map[string]interface{}{"length": float64(8)},
					},
				},
			},
		},
	}))
	if err != nil {
		t.Fatal(err)
	}

	var result struct {
		Password string `json:"password"`
	}
	if err := json.Unmarshal(response, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Password) != 8 {
		t.Fatalf("got password length %d, want 8", len(result.Password))
	}
	if strings.Trim(result.Password, "0123456789") != "" {
		t.Fatalf("expected only digits, got %q", result.Password)
	}
}

func TestNativeCoreGenerateRandomPassword(t *testing.T) {
	core := GetNativeCore()

	response, err := core.InnerCore.Invoke(context.Background(), mustMarshal(t, InvokeConfig{
		Invocation: Invocation{
			Parameters: Parameters{
				MethodName: "GeneratePassword",
				SerializedParams: map[string]interface{}{
					"recipe": map[string]interface{}{
						"type": "Random",
						"parameters": map[string]interface{}{
							"length":         float64(16),
							"includeDigits":  true,
							"includeSymbols": true,
						},
					},
				},
			},
		},
	}))
	if err != nil {
		t.Fatal(err)
	}

	var result struct {
		Password string `json:"password"`
	}
	if err := json.Unmarshal(response, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Password) != 16 {
		t.Fatalf("got password length %d, want 16", len(result.Password))
	}
	if !strings.ContainsAny(result.Password, "0123456789") {
		t.Fatalf("expected a digit in %q", result.Password)
	}
	if !strings.ContainsAny(result.Password, "!@#$%^&*_-+=:;,.?") {
		t.Fatalf("expected a symbol in %q", result.Password)
	}
}

func TestNativeCoreMemorablePasswordUnsupported(t *testing.T) {
	core := GetNativeCore()

	_, err := core.InnerCore.Invoke(context.Background(), mustMarshal(t, InvokeConfig{
		Invocation: Invocation{
			Parameters: Parameters{
				MethodName: "GeneratePassword",
				SerializedParams: map[string]interface{}{
					"recipe": map[string]interface{}{
						"type":       "Memorable",
						"parameters": map[string]interface{}{"wordCount": float64(4)},
					},
				},
			},
		},
	}))
	if err == nil {
		t.Fatal("expected unsupported method error")
	}
	if got, want := err.Error(), `{"name":"UnsupportedNativeMethod","message":"native core does not implement \"GeneratePassword\""}`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNativeCoreItemMethodsReachAuthBoundary(t *testing.T) {
	core := GetNativeCore()
	config := NewDefaultConfig()
	config.SAToken = testServiceAccountToken(t)

	id, err := core.InitClient(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		method string
		params map[string]interface{}
	}{
		{
			method: "ItemsArchive",
			params: map[string]interface{}{"vault_id": "abcdefghijklmnopqrstuvwx12", "item_id": "abcdefghijklmnopqrstuvwx34"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			_, err := core.Invoke(context.Background(), InvokeConfig{
				Invocation: Invocation{
					ClientID: id,
					Parameters: Parameters{
						MethodName:       tt.method,
						SerializedParams: tt.params,
					},
				},
			})
			if err == nil {
				t.Fatal("expected auth boundary error")
			}
			want := `{"name":"NativeMethodNotImplemented","message":"native core cannot run \"` + tt.method + `\" until its service-account route is implemented"}`
			if got := err.Error(); got != want {
				t.Fatalf("got %q, want %q", got, want)
			}
		})
	}
}

func TestNativeCoreItemReadDispatchPreservesProviderFields(t *testing.T) {
	sessionKey := []byte("12345678901234567890123456789012")
	muk := []byte("abcdefghijklmnopqrstuvwx12345678")
	keysetID := "abcdefghijklmnopqrstuvwx90"
	keysetKey := []byte("23456789012345678901234567890123")
	vaultID := "abcdefghijklmnopqrstuvwx12"
	vaultKey := []byte("34567890123456789012345678901234")
	item := nativeSecretTestEncryptedItemJSON(t, vaultID, vaultKey)
	server := nativeEncryptedItemServer(t, sessionKey, muk, keysetID, keysetKey, vaultID, vaultKey, map[string][]byte{
		"/api/v1/vault/abcdefghijklmnopqrstuvwx12/items/overviews":                 []byte(`[` + string(item) + `]`),
		"/api/v1/vault/abcdefghijklmnopqrstuvwx12/item/abcdefghijklmnopqrstuvwx34": item,
	})
	defer server.Close()

	core := GetNativeCore()
	config := NewDefaultConfig()
	config.SAToken = testServiceAccountToken(t)
	id, err := core.InitClient(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	native := core.InnerCore.(*NativeCore)
	client, err := native.client(*id)
	if err != nil {
		t.Fatal(err)
	}
	client.baseURL = nativeHTTPTestClient(t, server, sessionKey).baseURL
	client.httpClient = server.Client()
	client.session = &nativeSession{ID: "session-id", Key: sessionKey}
	client.keys = serviceAccountKeyMaterial{MUK: muk}

	listResponse, err := core.Invoke(context.Background(), InvokeConfig{
		Invocation: Invocation{
			ClientID: id,
			Parameters: Parameters{
				MethodName: "ItemsList",
				SerializedParams: map[string]interface{}{
					"vault_id": "abcdefghijklmnopqrstuvwx12",
					"filters": []interface{}{
						map[string]interface{}{
							"type": "ByState",
							"content": map[string]interface{}{
								"active":   true,
								"archived": false,
							},
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(*listResponse, `"category":"ApiCredentials"`) ||
		!strings.Contains(*listResponse, `"updatedAt":"2026-07-04T01:00:00Z"`) {
		t.Fatalf("provider fields not preserved in list response: %s", *listResponse)
	}

	getResponse, err := core.Invoke(context.Background(), InvokeConfig{
		Invocation: Invocation{
			ClientID: id,
			Parameters: Parameters{
				MethodName: "ItemsGet",
				SerializedParams: map[string]interface{}{
					"vault_id": "abcdefghijklmnopqrstuvwx12",
					"item_id":  "abcdefghijklmnopqrstuvwx34",
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(*getResponse, `"id":"credential"`) ||
		!strings.Contains(*getResponse, `"updatedAt":"2026-07-04T01:00:00Z"`) {
		t.Fatalf("provider fields not preserved in get response: %s", *getResponse)
	}
}

func TestNativeCoreItemWriteDispatchPreservesProviderFields(t *testing.T) {
	sessionKey := []byte("12345678901234567890123456789012")
	muk := []byte("abcdefghijklmnopqrstuvwx12345678")
	keysetID := "abcdefghijklmnopqrstuvwx34"
	keysetKey := []byte("23456789012345678901234567890123")
	vaultID := "abcdefghijklmnopqrstuvwx12"
	itemID := "abcdefghijklmnopqrstuvwx56"
	vaultKey := []byte("34567890123456789012345678901234")
	server := nativeItemWriteServer(t, sessionKey, muk, keysetID, keysetKey, vaultID, vaultKey)
	defer server.Close()

	core := GetNativeCore()
	config := NewDefaultConfig()
	config.SAToken = testServiceAccountToken(t)
	id, err := core.InitClient(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	native := core.InnerCore.(*NativeCore)
	client, err := native.client(*id)
	if err != nil {
		t.Fatal(err)
	}
	client.baseURL = nativeHTTPTestClient(t, server, sessionKey).baseURL
	client.httpClient = server.Client()
	client.session = &nativeSession{ID: "session-id", Key: sessionKey}
	client.keys = serviceAccountKeyMaterial{MUK: muk}

	createResponse, err := core.Invoke(context.Background(), InvokeConfig{
		Invocation: Invocation{
			ClientID: id,
			Parameters: Parameters{
				MethodName: "ItemsCreate",
				SerializedParams: map[string]interface{}{
					"params": map[string]interface{}{
						"vaultId":  vaultID,
						"title":    "keyring",
						"category": "ApiCredentials",
						"fields": []map[string]interface{}{
							{"id": "username", "title": "username", "fieldType": "Text", "value": "provider-key"},
							{"id": "credential", "title": "credential", "fieldType": "Concealed", "value": "dmFsdWU="},
							{"id": "type", "title": "type", "fieldType": "Menu", "value": "token"},
							{"id": "hostname", "title": "hostname", "fieldType": "Text", "value": "refresh token"},
						},
						"tags": []string{"keyring-1password"},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(*createResponse, `"title":"keyring"`) ||
		!strings.Contains(*createResponse, `"id":"credential"`) ||
		!strings.Contains(*createResponse, `"id":"type"`) ||
		!strings.Contains(*createResponse, `"value":"refresh token"`) ||
		!strings.Contains(*createResponse, `"tags":["keyring-1password"]`) {
		t.Fatalf("provider fields not preserved in create response: %s", *createResponse)
	}

	putResponse, err := core.Invoke(context.Background(), InvokeConfig{
		Invocation: Invocation{
			ClientID: id,
			Parameters: Parameters{
				MethodName: "ItemsPut",
				SerializedParams: map[string]interface{}{
					"item": map[string]interface{}{
						"id":       itemID,
						"vaultId":  vaultID,
						"version":  float64(2),
						"title":    "keyring",
						"category": "ApiCredentials",
						"fields": []map[string]interface{}{
							{"id": "username", "title": "username", "fieldType": "Text", "value": "provider-key"},
							{"id": "credential", "title": "credential", "fieldType": "Concealed", "value": "bmV3"},
							{"id": "type", "title": "type", "fieldType": "Menu", "value": "password"},
							{"id": "hostname", "title": "hostname", "fieldType": "Text", "value": "updated description"},
						},
						"tags": []string{"keyring-1password"},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(*putResponse, `"id":"`+itemID+`"`) ||
		!strings.Contains(*putResponse, `"version":2`) ||
		!strings.Contains(*putResponse, `"value":"bmV3"`) ||
		!strings.Contains(*putResponse, `"value":"updated description"`) {
		t.Fatalf("provider fields not preserved in put response: %s", *putResponse)
	}
}

func TestNativeCoreItemDeleteDispatchUsesAccountRoute(t *testing.T) {
	sessionKey := []byte("12345678901234567890123456789012")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Method, http.MethodDelete; got != want {
			t.Fatalf("got method %q, want %q", got, want)
		}
		if got, want := r.URL.String(), "/api/v1/vault/abcdefghijklmnopqrstuvwx12/item/abcdefghijklmnopqrstuvwx34"; got != want {
			t.Fatalf("got path %q, want %q", got, want)
		}
		if r.Header.Get("X-AgileBits-Session-ID") != "session-id" {
			t.Fatal("missing session header")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	core := GetNativeCore()
	config := NewDefaultConfig()
	config.SAToken = testServiceAccountToken(t)
	id, err := core.InitClient(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	native := core.InnerCore.(*NativeCore)
	client, err := native.client(*id)
	if err != nil {
		t.Fatal(err)
	}
	client.baseURL = nativeHTTPTestClient(t, server, sessionKey).baseURL
	client.httpClient = server.Client()
	client.session = &nativeSession{ID: "session-id", Key: sessionKey}

	response, err := core.Invoke(context.Background(), InvokeConfig{
		Invocation: Invocation{
			ClientID: id,
			Parameters: Parameters{
				MethodName: "ItemsDelete",
				SerializedParams: map[string]interface{}{
					"vault_id": "abcdefghijklmnopqrstuvwx12",
					"item_id":  "abcdefghijklmnopqrstuvwx34",
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if response == nil || *response != "null" {
		t.Fatalf("got response %v, want null", response)
	}
}

func TestNativeCoreInventoryMethodsReachAuthBoundary(t *testing.T) {
	core := GetNativeCore()
	config := NewDefaultConfig()
	config.SAToken = testServiceAccountToken(t)

	id, err := core.InitClient(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		method string
		params map[string]interface{}
	}{
		{
			method: "VaultsList",
			params: map[string]interface{}{"params": map[string]interface{}{"decryptDetails": true}},
		},
		{
			method: "VaultsGet",
			params: map[string]interface{}{"vault_id": "abcdefghijklmnopqrstuvwx12", "vault_params": map[string]interface{}{"accessors": true}},
		},
		{
			method: "GroupsGet",
			params: map[string]interface{}{"group_id": "abcdefghijklmnopqrstuvwx12", "group_params": map[string]interface{}{"vaultPermissions": true}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			_, err := core.Invoke(context.Background(), InvokeConfig{
				Invocation: Invocation{
					ClientID: id,
					Parameters: Parameters{
						MethodName:       tt.method,
						SerializedParams: tt.params,
					},
				},
			})
			if err == nil {
				t.Fatal("expected auth boundary error")
			}
			want := `{"name":"NativeMethodNotImplemented","message":"native core cannot run \"` + tt.method + `\" until its service-account route is implemented"}`
			if got := err.Error(); got != want {
				t.Fatalf("got %q, want %q", got, want)
			}
		})
	}
}

func TestNativeCoreInventoryMethodsValidateObjectIDs(t *testing.T) {
	core := GetNativeCore()

	tests := []struct {
		name   string
		method string
		params map[string]interface{}
		want   string
	}{
		{
			name:   "vault overview id",
			method: "VaultsGetOverview",
			params: map[string]interface{}{"vault_id": "vault"},
			want:   `{"name":"InvalidUserInput","message":"parameter \"vault_id\" must be a 26-character 1Password ID"}`,
		},
		{
			name:   "vault get id",
			method: "VaultsGet",
			params: map[string]interface{}{"vault_id": "vault"},
			want:   `{"name":"InvalidUserInput","message":"parameter \"vault_id\" must be a 26-character 1Password ID"}`,
		},
		{
			name:   "group get id",
			method: "GroupsGet",
			params: map[string]interface{}{"group_id": "group"},
			want:   `{"name":"InvalidUserInput","message":"parameter \"group_id\" must be a 26-character 1Password ID"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := core.InnerCore.Invoke(context.Background(), mustMarshal(t, InvokeConfig{
				Invocation: Invocation{
					Parameters: Parameters{
						MethodName:       tt.method,
						SerializedParams: tt.params,
					},
				},
			}))
			if err == nil {
				t.Fatal("expected validation error")
			}
			if got := err.Error(); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNativeCoreItemMethodsValidateParams(t *testing.T) {
	core := GetNativeCore()

	_, err := core.InnerCore.Invoke(context.Background(), mustMarshal(t, InvokeConfig{
		Invocation: Invocation{
			Parameters: Parameters{
				MethodName:       "ItemsGet",
				SerializedParams: map[string]interface{}{"vault_id": "abcdefghijklmnopqrstuvwx12"},
			},
		},
	}))
	if err == nil {
		t.Fatal("expected validation error")
	}
	if got, want := err.Error(), `{"name":"InvalidUserInput","message":"missing parameter \"item_id\""}`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNativeCoreItemMethodsValidateObjectIDs(t *testing.T) {
	core := GetNativeCore()

	tests := []struct {
		name   string
		method string
		params map[string]interface{}
		want   string
	}{
		{
			name:   "get vault id",
			method: "ItemsGet",
			params: map[string]interface{}{"vault_id": "vault", "item_id": "abcdefghijklmnopqrstuvwx34"},
			want:   `{"name":"InvalidUserInput","message":"parameter \"vault_id\" must be a 26-character 1Password ID"}`,
		},
		{
			name:   "create vault id",
			method: "ItemsCreate",
			params: map[string]interface{}{"params": map[string]interface{}{"vaultId": "vault"}},
			want:   `{"name":"InvalidUserInput","message":"parameter \"vaultId\" must be a 26-character 1Password ID"}`,
		},
		{
			name:   "put item id",
			method: "ItemsPut",
			params: map[string]interface{}{"item": map[string]interface{}{"id": "item", "vaultId": "abcdefghijklmnopqrstuvwx12"}},
			want:   `{"name":"InvalidUserInput","message":"parameter \"id\" must be a 26-character 1Password ID"}`,
		},
		{
			name:   "get all item id",
			method: "ItemsGetAll",
			params: map[string]interface{}{"vault_id": "abcdefghijklmnopqrstuvwx12", "item_ids": []interface{}{"item"}},
			want:   `{"name":"InvalidUserInput","message":"parameter \"item_ids[0]\" must be a 26-character 1Password ID"}`,
		},
		{
			name:   "create all vault id",
			method: "ItemsCreateAll",
			params: map[string]interface{}{"vault_id": "vault", "params": []interface{}{map[string]interface{}{"title": "keyring"}}},
			want:   `{"name":"InvalidUserInput","message":"parameter \"vault_id\" must be a 26-character 1Password ID"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := core.InnerCore.Invoke(context.Background(), mustMarshal(t, InvokeConfig{
				Invocation: Invocation{
					Parameters: Parameters{
						MethodName:       tt.method,
						SerializedParams: tt.params,
					},
				},
			}))
			if err == nil {
				t.Fatal("expected validation error")
			}
			if got := err.Error(); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNativeCoreItemMethodsValidateListFilters(t *testing.T) {
	core := GetNativeCore()

	_, err := core.InnerCore.Invoke(context.Background(), mustMarshal(t, InvokeConfig{
		Invocation: Invocation{
			Parameters: Parameters{
				MethodName: "ItemsList",
				SerializedParams: map[string]interface{}{
					"vault_id": "abcdefghijklmnopqrstuvwx12",
					"filters": []interface{}{
						map[string]interface{}{"type": "Unknown", "content": map[string]interface{}{}},
					},
				},
			},
		},
	}))
	if err == nil {
		t.Fatal("expected validation error")
	}
	if got, want := err.Error(), `{"name":"InvalidUserInput","message":"unsupported item list filter \"Unknown\""}`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNativeCoreRejectsMissingServiceAccountToken(t *testing.T) {
	core := GetNativeCore()
	config := NewDefaultConfig()

	_, err := core.InitClient(context.Background(), config)
	if err == nil {
		t.Fatal("expected missing token error")
	}
	if got, want := err.Error(), `{"name":"InvalidUserInput","message":"invalid user input: encountered the following errors: service account token was not specified"}`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNativeCoreReleaseUnknownClientIsNoop(t *testing.T) {
	core := GetNativeCore()
	core.ReleaseClient(99)
}

func TestNativeCoreReleaseClientRemovesClient(t *testing.T) {
	core := GetNativeCore()
	config := NewDefaultConfig()
	config.SAToken = testServiceAccountToken(t)

	id, err := core.InitClient(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	core.ReleaseClient(*id)

	_, err = core.Invoke(context.Background(), InvokeConfig{
		Invocation: Invocation{
			ClientID: id,
			Parameters: Parameters{
				MethodName:       "ItemsGet",
				SerializedParams: map[string]interface{}{"vault_id": "abcdefghijklmnopqrstuvwx12", "item_id": "abcdefghijklmnopqrstuvwx34"},
			},
		},
	})
	if err == nil {
		t.Fatal("expected released client id to be invalid")
	}
	if got, want := err.Error(), `{"name":"Internal","message":"invalid client id"}`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func mustMarshal(t *testing.T, value interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

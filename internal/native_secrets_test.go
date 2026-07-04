package internal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNativeSecretResolveRequest(t *testing.T) {
	request, err := nativeSecretResolveRequest(map[string]interface{}{
		"secret_reference": "op://vault/item/field",
	})
	if err != nil {
		t.Fatal(err)
	}
	if request.SecretReference != "op://vault/item/field" {
		t.Fatalf("got %q", request.SecretReference)
	}
	if request.Reference.Vault != "vault" || request.Reference.Item != "item" || request.Reference.Field != "field" {
		t.Fatalf("unexpected parsed reference: %+v", request.Reference)
	}

	_, err = nativeSecretResolveRequest(map[string]interface{}{
		"secret_reference": "vault/item/field",
	})
	if err == nil {
		t.Fatal("expected bad reference error")
	}
	if got, want := err.Error(), `secret reference is not prefixed with "op://"`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	_, err = nativeSecretResolveRequest(map[string]interface{}{
		"secret_reference": "op://vault/item/field?attribute=totp#fragment",
	})
	if err == nil {
		t.Fatal("expected fragment error")
	}
	if got, want := err.Error(), `fragments are not supported`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNativeSecretResolveAllRequest(t *testing.T) {
	request, err := nativeSecretResolveAllRequest(map[string]interface{}{
		"secret_references": []interface{}{
			"op://vault/item/field",
			"op://vault/item/section/field",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(request.SecretReferences) != 2 {
		t.Fatalf("got %d references, want 2", len(request.SecretReferences))
	}
	if got, want := request.References[1].Section, "section"; got != want {
		t.Fatalf("got section %q, want %q", got, want)
	}

	_, err = nativeSecretResolveAllRequest(map[string]interface{}{
		"secret_references": []interface{}{},
	})
	if err == nil {
		t.Fatal("expected empty references error")
	}
	if got, want := err.Error(), `parameter "secret_references" cannot be empty`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestParseNativeSecretReference(t *testing.T) {
	ref, err := parseNativeSecretReference("op://vault%20name/item%20name/section%20name/field%20name?attribute=totp")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := ref.Vault, "vault name"; got != want {
		t.Fatalf("got vault %q, want %q", got, want)
	}
	if got, want := ref.Item, "item name"; got != want {
		t.Fatalf("got item %q, want %q", got, want)
	}
	if got, want := ref.Section, "section name"; got != want {
		t.Fatalf("got section %q, want %q", got, want)
	}
	if got, want := ref.Field, "field name"; got != want {
		t.Fatalf("got field %q, want %q", got, want)
	}
	if got, want := ref.Attribute, "totp"; got != want {
		t.Fatalf("got attribute %q, want %q", got, want)
	}
}

func TestNativeSecretValueFromItem(t *testing.T) {
	sectionID := "database"
	item := nativeItemResponse{
		Fields: json.RawMessage(`[
			{"id":"username","title":"username","value":"root"},
			{"id":"password","title":"password","sectionId":"database","value":"secret"}
		]`),
		Sections: json.RawMessage(`[{"id":"database","title":"Database"}]`),
	}

	value, err := nativeSecretValueFromItem(item, nativeSecretReference{Field: "username"})
	if err != nil {
		t.Fatal(err)
	}
	if value != "root" {
		t.Fatalf("got %q, want root", value)
	}

	value, err = nativeSecretValueFromItem(item, nativeSecretReference{Section: "Database", Field: "password"})
	if err != nil {
		t.Fatal(err)
	}
	if value != "secret" {
		t.Fatalf("got %q, want secret", value)
	}

	value, err = nativeSecretValueFromItem(item, nativeSecretReference{Section: sectionID, Field: "password"})
	if err != nil {
		t.Fatal(err)
	}
	if value != "secret" {
		t.Fatalf("got %q, want secret", value)
	}
}

func TestNativeSecretValueFromItemRejectsAmbiguousField(t *testing.T) {
	item := nativeItemResponse{
		Fields: json.RawMessage(`[
			{"id":"token","title":"token","value":"one"},
			{"id":"token","title":"token","value":"two"}
		]`),
	}

	_, err := nativeSecretValueFromItem(item, nativeSecretReference{Field: "token"})
	if err == nil {
		t.Fatal("expected ambiguous field error")
	}
	if got, want := err.Error(), "too many matching fields"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNativeSecretValueFromItemRejectsUnsupportedAttribute(t *testing.T) {
	item := nativeItemResponse{
		Fields: json.RawMessage(`[{"id":"otp","title":"otp","value":"otpauth://example"}]`),
	}

	_, err := nativeSecretValueFromItem(item, nativeSecretReference{Field: "otp", Attribute: "totp"})
	if err == nil {
		t.Fatal("expected incompatible totp field error")
	}
	if got, want := err.Error(), `incompatibleTOTPQueryParameterField`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNativeSecretValueFromItemReturnsTOTPCode(t *testing.T) {
	item := nativeItemResponse{
		Fields: json.RawMessage(`[
			{
				"id":"otp",
				"title":"one-time password",
				"fieldType":"Totp",
				"value":"otpauth://example",
				"details":{"type":"Otp","content":{"code":"123456"}}
			}
		]`),
	}

	value, err := nativeSecretValueFromItem(item, nativeSecretReference{Field: "otp", Attribute: "totp"})
	if err != nil {
		t.Fatal(err)
	}
	if value != "123456" {
		t.Fatalf("got %q, want 123456", value)
	}
}

func TestNativeSecretValueFromItemRejectsMissingTOTPCode(t *testing.T) {
	item := nativeItemResponse{
		Fields: json.RawMessage(`[
			{
				"id":"otp",
				"title":"one-time password",
				"fieldType":"Totp",
				"value":"otpauth://example",
				"details":{"type":"Otp","content":{"errorMessage":"bad otp"}}
			}
		]`),
	}

	_, err := nativeSecretValueFromItem(item, nativeSecretReference{Field: "otp", Attribute: "totp"})
	if err == nil {
		t.Fatal("expected totp generation error")
	}
	if got, want := err.Error(), `unableToGenerateTotpCode`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNativeResolveSecretUsesReadRoutes(t *testing.T) {
	client, closeServer := nativeSecretResolveTestClient(t)
	defer closeServer()

	response, err := client.resolveSecret(context.Background(), nativeSecretResolveParams{
		SecretReference: "op://Private/keyring/credential",
		Reference: nativeSecretReference{
			Vault: "Private",
			Item:  "keyring",
			Field: "credential",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var secret string
	if err := json.Unmarshal(response, &secret); err != nil {
		t.Fatal(err)
	}
	if secret != "dmFsdWU=" {
		t.Fatalf("got %q, want dmFsdWU=", secret)
	}
}

func TestNativeResolveSecretWithIDsSkipsLists(t *testing.T) {
	sessionKey := []byte("12345678901234567890123456789012")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.URL.String(), "/api/v1/vault/abcdefghijklmnopqrstuvwx12/item/abcdefghijklmnopqrstuvwx34"; got != want {
			t.Fatalf("got path %q, want %q", got, want)
		}
		response, err := nativeSealSessionPayload("session-id", sessionKey, []byte("123456789012"), []byte(`{
			"id":"abcdefghijklmnopqrstuvwx34",
			"title":"keyring",
			"category":"API_CREDENTIAL",
			"vaultId":"abcdefghijklmnopqrstuvwx12",
			"fields":[{"id":"credential","title":"credential","value":"dmFsdWU="}]
		}`))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Fatal(err)
		}
	}))
	defer server.Close()

	client := nativeHTTPTestClient(t, server, sessionKey)
	response, err := client.resolveSecret(context.Background(), nativeSecretResolveParams{
		SecretReference: "op://abcdefghijklmnopqrstuvwx12/abcdefghijklmnopqrstuvwx34/credential",
		Reference: nativeSecretReference{
			Vault: "abcdefghijklmnopqrstuvwx12",
			Item:  "abcdefghijklmnopqrstuvwx34",
			Field: "credential",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var secret string
	if err := json.Unmarshal(response, &secret); err != nil {
		t.Fatal(err)
	}
	if secret != "dmFsdWU=" {
		t.Fatalf("got %q, want dmFsdWU=", secret)
	}
}

func TestNativeResolveSecretsPreservesPerReferenceErrors(t *testing.T) {
	client, closeServer := nativeSecretResolveTestClient(t)
	defer closeServer()

	response, err := client.resolveSecrets(context.Background(), nativeSecretResolveAllParams{
		SecretReferences: []string{
			"op://Private/keyring/credential",
			"op://Private/keyring/missing",
		},
		References: []nativeSecretReference{
			{Vault: "Private", Item: "keyring", Field: "credential"},
			{Vault: "Private", Item: "keyring", Field: "missing"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var got nativeResolveAllResponse
	if err := json.Unmarshal(response, &got); err != nil {
		t.Fatal(err)
	}
	if got.IndividualResponses["op://Private/keyring/credential"].Content == nil {
		t.Fatalf("expected content response: %+v", got)
	}
	missing := got.IndividualResponses["op://Private/keyring/missing"].Error
	if missing == nil || missing.Type != "fieldNotFound" {
		t.Fatalf("expected fieldNotFound, got %+v", missing)
	}
}

func TestNativeResolveSecretsPreservesTOTPErrorTypes(t *testing.T) {
	client, closeServer := nativeSecretResolveTestClient(t)
	defer closeServer()

	response, err := client.resolveSecrets(context.Background(), nativeSecretResolveAllParams{
		SecretReferences: []string{
			"op://Private/keyring/credential?attribute=totp",
			"op://Private/keyring/otp?attribute=totp",
		},
		References: []nativeSecretReference{
			{Vault: "Private", Item: "keyring", Field: "credential", Attribute: "totp"},
			{Vault: "Private", Item: "keyring", Field: "otp", Attribute: "totp"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var got nativeResolveAllResponse
	if err := json.Unmarshal(response, &got); err != nil {
		t.Fatal(err)
	}
	incompatible := got.IndividualResponses["op://Private/keyring/credential?attribute=totp"].Error
	if incompatible == nil || incompatible.Type != "incompatibleTOTPQueryParameterField" {
		t.Fatalf("expected incompatible TOTP error, got %+v", incompatible)
	}
	totp := got.IndividualResponses["op://Private/keyring/otp?attribute=totp"].Content
	if totp == nil || totp.Secret != "123456" {
		t.Fatalf("expected totp content, got %+v", totp)
	}
}

func nativeSecretResolveTestClient(t *testing.T) (*nativeClient, func()) {
	t.Helper()
	sessionKey := []byte("12345678901234567890123456789012")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var plaintext string
		switch r.URL.String() {
		case "/api/v1/vaults":
			plaintext = `[{"id":"abcdefghijklmnopqrstuvwx12","title":"Private"}]`
		case "/api/v1/vault/abcdefghijklmnopqrstuvwx12/items/overviews":
			plaintext = `[{"id":"abcdefghijklmnopqrstuvwx34","title":"keyring","category":"API_CREDENTIAL","vaultId":"abcdefghijklmnopqrstuvwx12","state":"active"}]`
		case "/api/v1/vault/abcdefghijklmnopqrstuvwx12/item/abcdefghijklmnopqrstuvwx34":
			plaintext = `{
				"id":"abcdefghijklmnopqrstuvwx34",
				"title":"keyring",
				"category":"API_CREDENTIAL",
				"vaultId":"abcdefghijklmnopqrstuvwx12",
				"fields":[
					{"id":"username","title":"username","value":"key"},
					{"id":"credential","title":"credential","value":"dmFsdWU="},
					{
						"id":"otp",
						"title":"one-time password",
						"fieldType":"Totp",
						"value":"otpauth://example",
						"details":{"type":"Otp","content":{"code":"123456"}}
					}
				]
			}`
		default:
			t.Fatalf("unexpected path %q", r.URL.String())
		}
		response, err := nativeSealSessionPayload("session-id", sessionKey, []byte("123456789012"), []byte(plaintext))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Fatal(err)
		}
	}))
	return nativeHTTPTestClient(t, server, sessionKey), server.Close
}

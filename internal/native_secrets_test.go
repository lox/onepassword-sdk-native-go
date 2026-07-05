package internal

import (
	"context"
	"encoding/json"
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
	muk := []byte("abcdefghijklmnopqrstuvwx12345678")
	keysetID := "abcdefghijklmnopqrstuvwx90"
	keysetKey := []byte("23456789012345678901234567890123")
	vaultID := "abcdefghijklmnopqrstuvwx12"
	vaultKey := []byte("34567890123456789012345678901234")
	// Only the single-item route (plus key material) is served: hitting a
	// vault or item list route fails the test.
	server := nativeEncryptedItemServer(t, sessionKey, muk, keysetID, keysetKey, vaultID, vaultKey, map[string][]byte{
		"/api/v1/vault/abcdefghijklmnopqrstuvwx12/item/abcdefghijklmnopqrstuvwx34": nativeSecretTestEncryptedItemJSON(t, vaultID, vaultKey),
	})
	defer server.Close()

	client := nativeHTTPTestClient(t, server, sessionKey)
	client.keys = serviceAccountKeyMaterial{MUK: muk}
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
	muk := []byte("abcdefghijklmnopqrstuvwx12345678")
	keysetID := "abcdefghijklmnopqrstuvwx90"
	keysetKey := []byte("23456789012345678901234567890123")
	vaultID := "abcdefghijklmnopqrstuvwx12"
	vaultKey := []byte("34567890123456789012345678901234")
	item := nativeSecretTestEncryptedItemJSON(t, vaultID, vaultKey)
	server := nativeEncryptedItemServer(t, sessionKey, muk, keysetID, keysetKey, vaultID, vaultKey, map[string][]byte{
		"/api/v1/vaults": []byte(`[{"id":"` + vaultID + `","title":"Private"}]`),
		"/api/v1/vault/" + vaultID + "/items/overviews":                 []byte(`[` + string(item) + `]`),
		"/api/v1/vault/" + vaultID + "/item/abcdefghijklmnopqrstuvwx34": item,
	})
	client := nativeHTTPTestClient(t, server, sessionKey)
	client.keys = serviceAccountKeyMaterial{MUK: muk}
	return client, server.Close
}

func nativeSecretTestEncryptedItemJSON(t *testing.T, vaultID string, vaultKey []byte) []byte {
	t.Helper()
	item := nativeEncryptedItemData{
		UUID:        "abcdefghijklmnopqrstuvwx34",
		Type:        "API_CREDENTIAL",
		ItemVersion: 2,
		EncryptedBy: vaultID,
		VaultKeySN:  1,
		CreatedAt:   json.RawMessage(`"2026-07-04T00:00:00Z"`),
		UpdatedAt:   json.RawMessage(`"2026-07-04T01:00:00Z"`),
		EncOverview: nativeTestEncryptedJWK(t, vaultID, vaultKey, []byte("345678901234"), []byte(`{
			"title":"keyring",
			"category":"API_CREDENTIAL",
			"state":"active"
		}`)),
		EncDetails: nativeTestEncryptedJWK(t, vaultID, vaultKey, []byte("456789012345"), []byte(`{
			"fields":[
				{"id":"username","title":"username","fieldType":"Text","value":"key"},
				{"id":"credential","title":"credential","fieldType":"Concealed","value":"dmFsdWU="},
				{
					"id":"otp",
					"title":"one-time password",
					"fieldType":"Totp",
					"value":"otpauth://example",
					"details":{"type":"Otp","content":{"code":"123456"}}
				}
			],
			"sections":[]
		}`)),
	}
	body, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

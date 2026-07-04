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

func TestNativeItemRequestsPreservePayload(t *testing.T) {
	create, err := nativeItemCreateRequest(map[string]interface{}{
		"params": map[string]interface{}{
			"vaultId": "abcdefghijklmnopqrstuvwx12",
			"title":   "keyring",
			"fields": []map[string]interface{}{
				{"id": "username", "value": "key"},
				{"id": "credential", "value": "dmFsdWU="},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(create.Params.Raw, []byte(`"title":"keyring"`)) {
		t.Fatalf("create payload lost title: %s", create.Params.Raw)
	}

	put, err := nativeItemPutRequest(map[string]interface{}{
		"item": map[string]interface{}{
			"id":      "abcdefghijklmnopqrstuvwx34",
			"vaultId": "abcdefghijklmnopqrstuvwx12",
			"title":   "keyring",
			"fields": []map[string]interface{}{
				{"id": "username", "value": "key"},
				{"id": "credential", "value": "dmFsdWU="},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(put.Item.Raw, []byte(`"title":"keyring"`)) {
		t.Fatalf("put payload lost title: %s", put.Item.Raw)
	}

	createAll, err := nativeItemCreateAllRequest(map[string]interface{}{
		"vault_id": "abcdefghijklmnopqrstuvwx12",
		"params": []map[string]interface{}{
			{
				"title": "keyring",
				"fields": []map[string]interface{}{
					{"id": "username", "value": "key"},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(createAll.Params) != 1 || !bytes.Contains(createAll.Params[0].Raw, []byte(`"title":"keyring"`)) {
		t.Fatalf("create all payload lost title: %+v", createAll.Params)
	}
}

func TestNativeItemRequestRejectsDuplicateFieldIDs(t *testing.T) {
	_, err := nativeItemCreateRequest(map[string]interface{}{
		"params": map[string]interface{}{
			"vaultId": "abcdefghijklmnopqrstuvwx12",
			"fields": []map[string]interface{}{
				{"id": "username", "value": "one"},
				{"id": "username", "value": "two"},
			},
		},
	})
	if err == nil {
		t.Fatal("expected duplicate field id error")
	}
	if got, want := err.Error(), `item field id "username" is duplicated`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	_, err = nativeItemCreateAllRequest(map[string]interface{}{
		"vault_id": "abcdefghijklmnopqrstuvwx12",
		"params": []map[string]interface{}{
			{
				"fields": []map[string]interface{}{
					{"id": "username", "value": "one"},
					{"id": "username", "value": "two"},
				},
			},
		},
	})
	if err == nil {
		t.Fatal("expected duplicate field id error")
	}
	if got, want := err.Error(), `params[0]: item field id "username" is duplicated`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNativeVaultItemsRequestValidatesIDs(t *testing.T) {
	request, err := nativeVaultItemsRequest(map[string]interface{}{
		"vault_id": "abcdefghijklmnopqrstuvwx12",
		"item_ids": []interface{}{
			"abcdefghijklmnopqrstuvwx34",
			"abcdefghijklmnopqrstuvwx56",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(request.ItemIDs) != 2 {
		t.Fatalf("got %d item ids, want 2", len(request.ItemIDs))
	}

	_, err = nativeVaultItemsRequest(map[string]interface{}{
		"vault_id": "abcdefghijklmnopqrstuvwx12",
		"item_ids": []interface{}{
			"bad",
		},
	})
	if err == nil {
		t.Fatal("expected bad item id error")
	}
	if got, want := err.Error(), `parameter "item_ids[0]" must be a 26-character 1Password ID`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNativeItemCreateAllRequestValidatesVault(t *testing.T) {
	_, err := nativeItemCreateAllRequest(map[string]interface{}{
		"vault_id": "abcdefghijklmnopqrstuvwx12",
		"params": []map[string]interface{}{
			{"vaultId": "abcdefghijklmnopqrstuvwx34"},
		},
	})
	if err == nil {
		t.Fatal("expected mismatched vault error")
	}
	if got, want := err.Error(), `params[0].vaultId must match vault_id`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNativeItemForCreateValidatesSuppliedID(t *testing.T) {
	item, err := nativeItemCreateRequest(map[string]interface{}{
		"params": map[string]interface{}{
			"id":      "not-an-item-id",
			"vaultId": "abcdefghijklmnopqrstuvwx12",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = nativeItemForCreate(item.Params, item.Params.VaultID)
	if err == nil {
		t.Fatal("expected invalid id error")
	}
	if got, want := err.Error(), `parameter "id" must be a 26-character 1Password ID`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNativeItemStateAllowed(t *testing.T) {
	activeOnly := []nativeItemListFilter{{
		Type:    "ByState",
		Content: nativeItemListFilterState{Active: true},
	}}
	if !nativeItemStateAllowed(activeOnly, "active") {
		t.Fatal("expected active item to pass active filter")
	}
	if !nativeItemStateAllowed(activeOnly, "") {
		t.Fatal("expected item with missing state to pass active filter")
	}
	if nativeItemStateAllowed(activeOnly, "archived") {
		t.Fatal("expected archived item to fail active filter")
	}
	if !nativeItemStateAllowed(nil, "archived") {
		t.Fatal("expected no filters to allow any state")
	}
}

func TestNativeEncodeItemOverviewsAppliesFilters(t *testing.T) {
	response, err := nativeEncodeItemOverviews([]nativeItemOverview{
		{
			ID:        "abcdefghijklmnopqrstuvwx12",
			Title:     "active",
			Category:  "API_CREDENTIAL",
			VaultID:   "abcdefghijklmnopqrstuvwx34",
			CreatedAt: json.RawMessage(`"2026-07-04T00:00:00Z"`),
			UpdatedAt: json.RawMessage(`"2026-07-04T01:00:00Z"`),
			State:     "active",
		},
		{
			ID:       "abcdefghijklmnopqrstuvwx56",
			Title:    "archived",
			Category: "API_CREDENTIAL",
			VaultID:  "abcdefghijklmnopqrstuvwx34",
			State:    "archived",
		},
	}, []nativeItemListFilter{{
		Type:    "ByState",
		Content: nativeItemListFilterState{Active: true},
	}})
	if err != nil {
		t.Fatal(err)
	}

	var got []nativeItemOverview
	if err := json.Unmarshal(response, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Title != "active" {
		t.Fatalf("unexpected filtered overviews: %+v", got)
	}
	if got[0].Category != "ApiCredentials" {
		t.Fatalf("got category %q, want ApiCredentials", got[0].Category)
	}
	if got[0].State != "active" {
		t.Fatalf("got state %q, want active", got[0].State)
	}
	if string(got[0].UpdatedAt) != `"2026-07-04T01:00:00Z"` {
		t.Fatalf("got updatedAt %s", got[0].UpdatedAt)
	}
}

func TestNativeEncodeItem(t *testing.T) {
	response, err := nativeEncodeItem(nativeItemResponse{
		ID:        "abcdefghijklmnopqrstuvwx12",
		Title:     "keyring",
		Category:  "API_CREDENTIAL",
		VaultID:   "abcdefghijklmnopqrstuvwx34",
		Fields:    json.RawMessage(`[{"id":"username","value":"key"}]`),
		Document:  json.RawMessage(`{"id":"file","name":"doc.txt","size":12}`),
		CreatedAt: json.RawMessage(`"2026-07-04T00:00:00Z"`),
		UpdatedAt: json.RawMessage(`"2026-07-04T01:00:00Z"`),
	})
	if err != nil {
		t.Fatal(err)
	}

	var got nativeItemResponse
	if err := json.Unmarshal(response, &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != "abcdefghijklmnopqrstuvwx12" || got.VaultID != "abcdefghijklmnopqrstuvwx34" {
		t.Fatalf("unexpected item response: %+v", got)
	}
	if got.Category != "ApiCredentials" {
		t.Fatalf("got category %q, want ApiCredentials", got.Category)
	}
	if !bytes.Contains(response, []byte(`"fields":[{"id":"username","value":"key"}]`)) {
		t.Fatalf("item response lost fields: %s", response)
	}
	if !bytes.Contains(response, []byte(`"document":{"id":"file","name":"doc.txt","size":12}`)) {
		t.Fatalf("item response lost document: %s", response)
	}
	if string(got.UpdatedAt) != `"2026-07-04T01:00:00Z"` {
		t.Fatalf("got updatedAt %s", got.UpdatedAt)
	}
}

func TestNativeItemFieldValue(t *testing.T) {
	item := nativeItemResponse{
		Fields: json.RawMessage(`[
			{"id":"username","title":"username","value":"key"},
			{"id":"credential","title":"credential","value":"dmFsdWU="}
		]`),
	}
	if got, ok := nativeItemFieldValue(item, "username"); !ok || got != "key" {
		t.Fatalf("got username %q, ok %v", got, ok)
	}
	if got, ok := nativeItemFieldValue(item, "credential"); !ok || got != "dmFsdWU=" {
		t.Fatalf("got credential %q, ok %v", got, ok)
	}

	titleOnly := nativeItemResponse{Fields: json.RawMessage(`[{"title":"hostname","value":"host"}]`)}
	if got, ok := nativeItemFieldValue(titleOnly, "hostname"); !ok || got != "host" {
		t.Fatalf("got hostname %q, ok %v", got, ok)
	}
}

func TestNativeItemOverviewMatches(t *testing.T) {
	overview := nativeItemOverview{
		Title:    "example-keyring",
		Category: "ApiCredentials",
		Tags:     []string{"keyring-1password"},
	}
	if !nativeItemOverviewMatches(overview, "example-keyring", "ApiCredentials", "keyring-1password") {
		t.Fatal("expected matching overview")
	}
	if nativeItemOverviewMatches(overview, "other", "ApiCredentials", "keyring-1password") {
		t.Fatal("unexpected title match")
	}
	if nativeItemOverviewMatches(overview, "example-keyring", "ApiCredentials", "other") {
		t.Fatal("unexpected tag match")
	}
}

func TestNativeListItemsUsesAccountRoute(t *testing.T) {
	sessionKey := []byte("12345678901234567890123456789012")
	muk := []byte("abcdefghijklmnopqrstuvwx12345678")
	keysetID := "abcdefghijklmnopqrstuvwx90"
	keysetKey := []byte("23456789012345678901234567890123")
	vaultID := "abcdefghijklmnopqrstuvwx12"
	vaultKey := []byte("34567890123456789012345678901234")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Method, http.MethodGet; got != want {
			t.Fatalf("got method %q, want %q", got, want)
		}
		if r.Header.Get("X-AgileBits-Session-ID") != "session-id" {
			t.Fatalf("missing session header")
		}
		var plaintext []byte
		switch r.URL.String() {
		case "/api/v2/account/keysets":
			plaintext = []byte(`{"keysets":[` + string(nativeTestKeysetJSON(t, keysetID, "mp", muk, keysetKey)) + `]}`)
		case "/api/v1/objects/" + vaultID + "/access/combined":
			plaintext = []byte(`{"access":[` + string(nativeTestVaultAccessJSON(t, vaultID, keysetID, keysetKey, vaultKey)) + `]}`)
		case "/api/v1/vault/" + vaultID + "/items/overviews":
			plaintext = []byte(`[` + string(nativeTestEncryptedItemJSON(t, vaultID, vaultKey, false)) + `]`)
		default:
			t.Fatalf("unexpected path %q", r.URL.String())
		}
		response, err := nativeSealSessionPayload("session-id", sessionKey, []byte("123456789012"), plaintext)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Fatal(err)
		}
	}))
	defer server.Close()

	client := nativeHTTPTestClient(t, server, sessionKey)
	client.keys = serviceAccountKeyMaterial{MUK: muk}
	response, err := client.listItems(context.Background(), nativeItemsListParams{
		VaultID: "abcdefghijklmnopqrstuvwx12",
		Filters: []nativeItemListFilter{{
			Type:    "ByState",
			Content: nativeItemListFilterState{Active: true},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []nativeItemOverview
	if err := json.Unmarshal(response, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Category != "ApiCredentials" {
		t.Fatalf("unexpected list response: %+v", got)
	}
}

func TestNativeGetItemUsesAccountRoute(t *testing.T) {
	sessionKey := []byte("12345678901234567890123456789012")
	muk := []byte("abcdefghijklmnopqrstuvwx12345678")
	keysetID := "abcdefghijklmnopqrstuvwx90"
	keysetKey := []byte("23456789012345678901234567890123")
	vaultID := "abcdefghijklmnopqrstuvwx12"
	vaultKey := []byte("34567890123456789012345678901234")
	server := nativeEncryptedItemServer(t, sessionKey, muk, keysetID, keysetKey, vaultID, vaultKey, map[string][]byte{
		"/api/v1/vault/abcdefghijklmnopqrstuvwx12/item/abcdefghijklmnopqrstuvwx34": nativeSecretTestEncryptedItemJSON(t, vaultID, vaultKey),
	})
	defer server.Close()

	client := nativeHTTPTestClient(t, server, sessionKey)
	client.keys = serviceAccountKeyMaterial{MUK: muk}
	response, err := client.getItem(context.Background(), nativeVaultItemParams{
		VaultID: "abcdefghijklmnopqrstuvwx12",
		ItemID:  "abcdefghijklmnopqrstuvwx34",
	})
	if err != nil {
		t.Fatal(err)
	}
	var got nativeItemResponse
	if err := json.Unmarshal(response, &got); err != nil {
		t.Fatal(err)
	}
	if got.Category != "ApiCredentials" || got.ID != "abcdefghijklmnopqrstuvwx34" {
		t.Fatalf("unexpected get response: %+v", got)
	}
}

func TestNativeGetItemsUsesSingleItemRoute(t *testing.T) {
	sessionKey := []byte("12345678901234567890123456789012")
	muk := []byte("abcdefghijklmnopqrstuvwx12345678")
	keysetID := "abcdefghijklmnopqrstuvwx90"
	keysetKey := []byte("23456789012345678901234567890123")
	vaultID := "abcdefghijklmnopqrstuvwx12"
	vaultKey := []byte("34567890123456789012345678901234")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var plaintext []byte
		switch r.URL.String() {
		case "/api/v2/account/keysets":
			plaintext = []byte(`{"keysets":[` + string(nativeTestKeysetJSON(t, keysetID, "mp", muk, keysetKey)) + `]}`)
		case "/api/v1/objects/" + vaultID + "/access/combined":
			plaintext = []byte(`{"access":[` + string(nativeTestVaultAccessJSON(t, vaultID, keysetID, keysetKey, vaultKey)) + `]}`)
		case "/api/v1/vault/abcdefghijklmnopqrstuvwx12/item/abcdefghijklmnopqrstuvwx34":
			plaintext = nativeSecretTestEncryptedItemJSON(t, vaultID, vaultKey)
		case "/api/v1/vault/abcdefghijklmnopqrstuvwx12/item/abcdefghijklmnopqrstuvwx56":
			http.NotFound(w, r)
			return
		default:
			t.Fatalf("unexpected path %q", r.URL.String())
		}
		response, err := nativeSealSessionPayload("session-id", sessionKey, []byte("123456789012"), plaintext)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Fatal(err)
		}
	}))
	defer server.Close()

	client := nativeHTTPTestClient(t, server, sessionKey)
	client.keys = serviceAccountKeyMaterial{MUK: muk}
	response, err := client.getItems(context.Background(), nativeVaultItemsParams{
		VaultID: "abcdefghijklmnopqrstuvwx12",
		ItemIDs: []string{
			"abcdefghijklmnopqrstuvwx34",
			"abcdefghijklmnopqrstuvwx56",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var got nativeItemsGetAllResponse
	if err := json.Unmarshal(response, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.IndividualResponses) != 2 {
		t.Fatalf("got %d responses, want 2", len(got.IndividualResponses))
	}
	if got.IndividualResponses[0].Content == nil || got.IndividualResponses[0].Content.Category != "ApiCredentials" {
		t.Fatalf("unexpected first response: %+v", got.IndividualResponses[0])
	}
	if got.IndividualResponses[1].Error == nil || got.IndividualResponses[1].Error.Type != "itemNotFound" {
		t.Fatalf("unexpected second response: %+v", got.IndividualResponses[1])
	}
}

func TestNativeListItemsDecryptsEncryptedOverviews(t *testing.T) {
	sessionKey := []byte("12345678901234567890123456789012")
	muk := []byte("abcdefghijklmnopqrstuvwx12345678")
	keysetID := "abcdefghijklmnopqrstuvwx34"
	keysetKey := []byte("23456789012345678901234567890123")
	vaultID := "abcdefghijklmnopqrstuvwx12"
	vaultKey := []byte("34567890123456789012345678901234")
	server := nativeEncryptedItemServer(t, sessionKey, muk, keysetID, keysetKey, vaultID, vaultKey, map[string][]byte{
		"/api/v1/vault/abcdefghijklmnopqrstuvwx12/items/overviews": []byte(`[` + string(nativeTestEncryptedItemJSON(t, vaultID, vaultKey, false)) + `]`),
	})
	defer server.Close()

	client := nativeHTTPTestClient(t, server, sessionKey)
	client.keys = serviceAccountKeyMaterial{MUK: muk}
	response, err := client.listItems(context.Background(), nativeItemsListParams{
		VaultID: "abcdefghijklmnopqrstuvwx12",
		Filters: []nativeItemListFilter{{
			Type:    "ByState",
			Content: nativeItemListFilterState{Active: true},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []nativeItemOverview
	if err := json.Unmarshal(response, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Title != "keyring" || got[0].Category != "ApiCredentials" {
		t.Fatalf("unexpected overviews: %+v", got)
	}
}

func TestNativeListItemsDecryptsEncryptedOverviewsBatchEnvelope(t *testing.T) {
	sessionKey := []byte("12345678901234567890123456789012")
	muk := []byte("abcdefghijklmnopqrstuvwx12345678")
	keysetID := "abcdefghijklmnopqrstuvwx34"
	keysetKey := []byte("23456789012345678901234567890123")
	vaultID := "abcdefghijklmnopqrstuvwx12"
	vaultKey := []byte("34567890123456789012345678901234")
	server := nativeEncryptedItemServer(t, sessionKey, muk, keysetID, keysetKey, vaultID, vaultKey, map[string][]byte{
		"/api/v1/vault/abcdefghijklmnopqrstuvwx12/items/overviews": []byte(`{
			"batchComplete":true,
			"deletedItemUuids":["abcdefghijklmnopqrstuvwx78"],
			"items":[` + string(nativeTestEncryptedItemJSON(t, vaultID, vaultKey, false)) + `]
		}`),
	})
	defer server.Close()

	client := nativeHTTPTestClient(t, server, sessionKey)
	client.keys = serviceAccountKeyMaterial{MUK: muk}
	response, err := client.listItems(context.Background(), nativeItemsListParams{
		VaultID: "abcdefghijklmnopqrstuvwx12",
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []nativeItemOverview
	if err := json.Unmarshal(response, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Title != "keyring" || got[0].Category != "ApiCredentials" {
		t.Fatalf("unexpected overviews: %+v", got)
	}
}

func TestNativeGetItemDecryptsEncryptedDetails(t *testing.T) {
	sessionKey := []byte("12345678901234567890123456789012")
	muk := []byte("abcdefghijklmnopqrstuvwx12345678")
	keysetID := "abcdefghijklmnopqrstuvwx34"
	keysetKey := []byte("23456789012345678901234567890123")
	vaultID := "abcdefghijklmnopqrstuvwx12"
	vaultKey := []byte("34567890123456789012345678901234")
	server := nativeEncryptedItemServer(t, sessionKey, muk, keysetID, keysetKey, vaultID, vaultKey, map[string][]byte{
		"/api/v1/vault/abcdefghijklmnopqrstuvwx12/item/abcdefghijklmnopqrstuvwx56": []byte(`{"item":` + string(nativeTestEncryptedItemJSON(t, vaultID, vaultKey, true)) + `}`),
	})
	defer server.Close()

	client := nativeHTTPTestClient(t, server, sessionKey)
	client.keys = serviceAccountKeyMaterial{MUK: muk}
	response, err := client.getItem(context.Background(), nativeVaultItemParams{
		VaultID: "abcdefghijklmnopqrstuvwx12",
		ItemID:  "abcdefghijklmnopqrstuvwx56",
	})
	if err != nil {
		t.Fatal(err)
	}
	var got nativeItemResponse
	if err := json.Unmarshal(response, &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != "abcdefghijklmnopqrstuvwx56" || got.Title != "keyring" || got.Category != "ApiCredentials" {
		t.Fatalf("unexpected item: %+v", got)
	}
	if !bytes.Contains(got.Fields, []byte(`"id":"credential"`)) {
		t.Fatalf("fields were not decrypted: %s", got.Fields)
	}
}

func TestNativeEncryptItemPayloadRoundTripsThroughDecryptItem(t *testing.T) {
	request, err := nativeItemCreateRequest(map[string]interface{}{
		"params": map[string]interface{}{
			"id":       "abcdefghijklmnopqrstuvwx56",
			"vaultId":  "abcdefghijklmnopqrstuvwx12",
			"title":    "keyring",
			"category": "ApiCredentials",
			"tags":     []string{"keyring-1password"},
			"fields": []map[string]interface{}{
				{"id": "username", "title": "username", "fieldType": "Text", "value": "provider-key"},
				{"id": "credential", "title": "credential", "fieldType": "Concealed", "value": "dmFsdWU="},
			},
			"sections": []map[string]interface{}{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	vaultKey := nativeSymmetricKey{
		ID:  "abcdefghijklmnopqrstuvwx12",
		Key: []byte("34567890123456789012345678901234"),
	}
	encrypted, err := nativeEncryptItemPayloadWithIVs(
		request.Params,
		1,
		vaultKey,
		[]byte("345678901234"),
		[]byte("456789012345"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if encrypted.Type != "API_CREDENTIAL" || encrypted.EncryptedBy != vaultKey.ID || encrypted.VaultKeySN != 1 {
		t.Fatalf("unexpected encrypted item metadata: %+v", encrypted)
	}

	got, err := encrypted.decryptItem("abcdefghijklmnopqrstuvwx12", map[int]nativeSymmetricKey{1: vaultKey})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "abcdefghijklmnopqrstuvwx56" || got.Title != "keyring" || got.Category != "ApiCredentials" {
		t.Fatalf("unexpected decrypted item: %+v", got)
	}
	if !bytes.Contains(got.Fields, []byte(`"id":"credential"`)) {
		t.Fatalf("fields were not encrypted/decrypted: %s", got.Fields)
	}
}

func TestNativeClientEncryptItemForWriteUnlocksVaultKey(t *testing.T) {
	sessionKey := []byte("12345678901234567890123456789012")
	muk := []byte("abcdefghijklmnopqrstuvwx12345678")
	keysetID := "abcdefghijklmnopqrstuvwx34"
	keysetKey := []byte("23456789012345678901234567890123")
	vaultID := "abcdefghijklmnopqrstuvwx12"
	vaultKeyBytes := []byte("34567890123456789012345678901234")
	server := nativeEncryptedItemServer(t, sessionKey, muk, keysetID, keysetKey, vaultID, vaultKeyBytes, nil)
	defer server.Close()

	request, err := nativeItemCreateRequest(map[string]interface{}{
		"params": map[string]interface{}{
			"id":       "abcdefghijklmnopqrstuvwx56",
			"vaultId":  vaultID,
			"title":    "keyring",
			"category": "ApiCredentials",
			"fields": []map[string]interface{}{
				{"id": "credential", "title": "credential", "fieldType": "Concealed", "value": "dmFsdWU="},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	client := nativeHTTPTestClient(t, server, sessionKey)
	client.keys = serviceAccountKeyMaterial{MUK: muk}
	encrypted, err := client.encryptItemForWrite(context.Background(), request.Params)
	if err != nil {
		t.Fatal(err)
	}
	if encrypted.VaultKeySN != 1 || encrypted.EncryptedBy != vaultID {
		t.Fatalf("unexpected encrypted item key metadata: %+v", encrypted)
	}

	item, err := encrypted.decryptItem(vaultID, map[int]nativeSymmetricKey{1: {ID: vaultID, Key: vaultKeyBytes}})
	if err != nil {
		t.Fatal(err)
	}
	if item.Title != "keyring" || item.Category != "ApiCredentials" {
		t.Fatalf("unexpected decrypted write-prep item: %+v", item)
	}
}

func TestNativeCreateItemPatchesEncryptedVaultItems(t *testing.T) {
	sessionKey := []byte("12345678901234567890123456789012")
	muk := []byte("abcdefghijklmnopqrstuvwx12345678")
	keysetID := "abcdefghijklmnopqrstuvwx34"
	keysetKey := []byte("23456789012345678901234567890123")
	vaultID := "abcdefghijklmnopqrstuvwx12"
	vaultKeyBytes := []byte("34567890123456789012345678901234")
	server := nativeItemWriteServer(t, sessionKey, muk, keysetID, keysetKey, vaultID, vaultKeyBytes)
	defer server.Close()

	request, err := nativeItemCreateRequest(map[string]interface{}{
		"params": map[string]interface{}{
			"vaultId":  vaultID,
			"title":    "keyring",
			"category": "ApiCredentials",
			"fields": []map[string]interface{}{
				{"id": "credential", "title": "credential", "fieldType": "Concealed", "value": "dmFsdWU="},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	client := nativeHTTPTestClient(t, server, sessionKey)
	client.keys = serviceAccountKeyMaterial{MUK: muk}
	response, err := client.createItem(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	var got nativeItemResponse
	if err := json.Unmarshal(response, &got); err != nil {
		t.Fatal(err)
	}
	if got.ID == "" || got.Title != "keyring" || got.Category != "ApiCredentials" || got.VaultID != vaultID {
		t.Fatalf("unexpected created item: %+v", got)
	}
}

func TestNativePutItemPatchesEncryptedVaultItems(t *testing.T) {
	sessionKey := []byte("12345678901234567890123456789012")
	muk := []byte("abcdefghijklmnopqrstuvwx12345678")
	keysetID := "abcdefghijklmnopqrstuvwx34"
	keysetKey := []byte("23456789012345678901234567890123")
	vaultID := "abcdefghijklmnopqrstuvwx12"
	itemID := "abcdefghijklmnopqrstuvwx56"
	vaultKeyBytes := []byte("34567890123456789012345678901234")
	server := nativeItemWriteServer(t, sessionKey, muk, keysetID, keysetKey, vaultID, vaultKeyBytes)
	defer server.Close()

	request, err := nativeItemPutRequest(map[string]interface{}{
		"item": map[string]interface{}{
			"id":       itemID,
			"vaultId":  vaultID,
			"version":  float64(2),
			"title":    "keyring",
			"category": "ApiCredentials",
			"fields": []map[string]interface{}{
				{"id": "credential", "title": "credential", "fieldType": "Concealed", "value": "dmFsdWU="},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	client := nativeHTTPTestClient(t, server, sessionKey)
	client.keys = serviceAccountKeyMaterial{MUK: muk}
	response, err := client.putItem(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	var got nativeItemResponse
	if err := json.Unmarshal(response, &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != itemID || got.Version != 2 || got.Title != "keyring" || got.Category != "ApiCredentials" {
		t.Fatalf("unexpected updated item: %+v", got)
	}
}

func TestNativeCreateItemsPatchesEncryptedVaultItems(t *testing.T) {
	sessionKey := []byte("12345678901234567890123456789012")
	muk := []byte("abcdefghijklmnopqrstuvwx12345678")
	keysetID := "abcdefghijklmnopqrstuvwx34"
	keysetKey := []byte("23456789012345678901234567890123")
	vaultID := "abcdefghijklmnopqrstuvwx12"
	vaultKeyBytes := []byte("34567890123456789012345678901234")
	server := nativeItemWriteServer(t, sessionKey, muk, keysetID, keysetKey, vaultID, vaultKeyBytes)
	defer server.Close()

	request, err := nativeItemCreateAllRequest(map[string]interface{}{
		"vault_id": vaultID,
		"params": []map[string]interface{}{
			{"id": "abcdefghijklmnopqrstuvwx56", "title": "one", "category": "ApiCredentials"},
			{"id": "abcdefghijklmnopqrstuvwx78", "title": "two", "category": "ApiCredentials"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	client := nativeHTTPTestClient(t, server, sessionKey)
	client.keys = serviceAccountKeyMaterial{MUK: muk}
	response, err := client.createItems(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	var got nativeItemsUpdateAllResponse
	if err := json.Unmarshal(response, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.IndividualResponses) != 2 ||
		got.IndividualResponses[0].Content == nil ||
		got.IndividualResponses[1].Content == nil {
		t.Fatalf("unexpected create all response: %+v", got)
	}
	if got.IndividualResponses[0].Content.Title != "one" || got.IndividualResponses[1].Content.Title != "two" {
		t.Fatalf("responses were not in request order: %+v", got.IndividualResponses)
	}
}

func TestNativeCreateItemsMatchesItemUUIDFailures(t *testing.T) {
	vaultID := "abcdefghijklmnopqrstuvwx12"
	vaultKey := nativeSymmetricKey{
		ID:  vaultID,
		Key: []byte("34567890123456789012345678901234"),
	}
	success := nativeTestEncryptedItemJSON(t, vaultID, vaultKey.Key, true)
	var updated nativeEncryptedItemData
	if err := json.Unmarshal(success, &updated); err != nil {
		t.Fatal(err)
	}
	updated.UUID = "abcdefghijklmnopqrstuvwx56"

	response := nativePatchVaultItemsResponse{
		UpdatedItems: []nativeEncryptedItemData{updated},
		FailedItems: []nativePatchItemFailure{{
			ItemUUID: "abcdefghijklmnopqrstuvwx78",
			Reason:   "itemStatusTooBig",
		}},
	}
	items := []nativeItemObject{
		{ID: "abcdefghijklmnopqrstuvwx56"},
		{ID: "abcdefghijklmnopqrstuvwx78"},
	}

	out := nativeItemsUpdateAllResponseFromPatch(vaultID, items, response, map[int]nativeSymmetricKey{1: vaultKey})
	if out.IndividualResponses[0].Content == nil {
		t.Fatalf("expected first response content: %+v", out)
	}
	err := out.IndividualResponses[1].Error
	if err == nil || err.Type != "itemValidationError" {
		t.Fatalf("expected itemValidationError from itemUuid failure, got %+v", err)
	}
}

func TestNativePatchedItemDecryptsRequestedItem(t *testing.T) {
	vaultID := "abcdefghijklmnopqrstuvwx12"
	vaultKey := nativeSymmetricKey{
		ID:  vaultID,
		Key: []byte("34567890123456789012345678901234"),
	}
	encrypted := nativeTestEncryptedItemJSON(t, vaultID, vaultKey.Key, true)
	var updated nativeEncryptedItemData
	if err := json.Unmarshal(encrypted, &updated); err != nil {
		t.Fatal(err)
	}
	extra := updated
	extra.UUID = "abcdefghijklmnopqrstuvwx78"

	item, err := nativePatchedItem(nativePatchVaultItemsResponse{
		ContentVersion: 43,
		UpdatedItems:   []nativeEncryptedItemData{extra, updated},
	}, vaultID, "abcdefghijklmnopqrstuvwx56", map[int]nativeSymmetricKey{1: vaultKey})
	if err != nil {
		t.Fatal(err)
	}
	if item.ID != "abcdefghijklmnopqrstuvwx56" || item.Title != "keyring" || item.Category != "ApiCredentials" {
		t.Fatalf("unexpected patched item: %+v", item)
	}
}

func TestNativePatchedItemMapsFailure(t *testing.T) {
	_, err := nativePatchedItem(nativePatchVaultItemsResponse{
		FailedItems: []nativePatchItemFailure{{
			UUID:   "abcdefghijklmnopqrstuvwx56",
			Reason: "itemStatusIncorrectItemVersion",
		}},
	}, "abcdefghijklmnopqrstuvwx12", "abcdefghijklmnopqrstuvwx56", nil)
	if err == nil {
		t.Fatal("expected patch failure")
	}
	if got, want := err.Error(), `{"name":"Conflict","message":"itemStatusIncorrectItemVersion"}`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNativePatchedItemMapsTooBigFailure(t *testing.T) {
	_, err := nativePatchedItem(nativePatchVaultItemsResponse{
		FailedItems: []nativePatchItemFailure{{
			UUID:   "abcdefghijklmnopqrstuvwx56",
			Reason: "itemStatusTooBig",
		}},
	}, "abcdefghijklmnopqrstuvwx12", "abcdefghijklmnopqrstuvwx56", nil)
	if err == nil {
		t.Fatal("expected patch failure")
	}
	if got, want := err.Error(), `{"name":"InvalidUserInput","message":"itemStatusTooBig"}`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNativeDeleteItemUsesAccountRoute(t *testing.T) {
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

	client := nativeHTTPTestClient(t, server, sessionKey)
	response, err := client.deleteItem(context.Background(), nativeVaultItemParams{
		VaultID: "abcdefghijklmnopqrstuvwx12",
		ItemID:  "abcdefghijklmnopqrstuvwx34",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(response), "null"; got != want {
		t.Fatalf("got response %q, want %q", got, want)
	}
}

func TestNativeDeleteItemsUsesSingleItemRoute(t *testing.T) {
	sessionKey := []byte("12345678901234567890123456789012")
	seen := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Method, http.MethodDelete; got != want {
			t.Fatalf("got method %q, want %q", got, want)
		}
		seen[r.URL.String()] = true
		switch r.URL.String() {
		case "/api/v1/vault/abcdefghijklmnopqrstuvwx12/item/abcdefghijklmnopqrstuvwx34":
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/vault/abcdefghijklmnopqrstuvwx12/item/abcdefghijklmnopqrstuvwx56":
			http.NotFound(w, r)
		default:
			t.Fatalf("unexpected path %q", r.URL.String())
		}
	}))
	defer server.Close()

	client := nativeHTTPTestClient(t, server, sessionKey)
	response, err := client.deleteItems(context.Background(), nativeVaultItemsParams{
		VaultID: "abcdefghijklmnopqrstuvwx12",
		ItemIDs: []string{
			"abcdefghijklmnopqrstuvwx34",
			"abcdefghijklmnopqrstuvwx56",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 {
		t.Fatalf("got %d delete requests, want 2", len(seen))
	}
	var got nativeItemsDeleteAllResponse
	if err := json.Unmarshal(response, &got); err != nil {
		t.Fatal(err)
	}
	if got.IndividualResponses["abcdefghijklmnopqrstuvwx34"].Content == nil {
		t.Fatalf("expected success content: %+v", got.IndividualResponses["abcdefghijklmnopqrstuvwx34"])
	}
	missing := got.IndividualResponses["abcdefghijklmnopqrstuvwx56"].Error
	if missing == nil || missing.Type != "itemNotFound" {
		t.Fatalf("expected itemNotFound error: %+v", got.IndividualResponses["abcdefghijklmnopqrstuvwx56"])
	}
}

func nativeHTTPTestClient(t *testing.T, server *httptest.Server, sessionKey []byte) *nativeClient {
	t.Helper()
	baseURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &nativeClient{
		baseURL:    baseURL,
		httpClient: server.Client(),
		session:    &nativeSession{ID: "session-id", Key: sessionKey},
	}
}

func nativeEncryptedItemServer(t *testing.T, sessionKey, muk []byte, keysetID string, keysetKey []byte, vaultID string, vaultKey []byte, payloads map[string][]byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var plaintext []byte
		switch r.URL.String() {
		case "/api/v2/account/keysets":
			plaintext = []byte(`{"keysets":[` + string(nativeTestKeysetJSON(t, keysetID, "mp", muk, keysetKey)) + `]}`)
		case "/api/v1/objects/" + vaultID + "/access/combined":
			plaintext = []byte(`{"access":[` + string(nativeTestVaultAccessJSON(t, vaultID, keysetID, keysetKey, vaultKey)) + `]}`)
		default:
			var ok bool
			plaintext, ok = payloads[r.URL.String()]
			if !ok {
				t.Fatalf("unexpected path %q", r.URL.String())
			}
		}
		response, err := nativeSealSessionPayload("session-id", sessionKey, []byte("123456789012"), plaintext)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Fatal(err)
		}
	}))
}

func nativeItemWriteServer(t *testing.T, sessionKey, muk []byte, keysetID string, keysetKey []byte, vaultID string, vaultKey []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var plaintext []byte
		switch r.URL.String() {
		case "/api/v1/vaults":
			plaintext = []byte(`[{"id":"` + vaultID + `","contentVersion":42}]`)
		case "/api/v2/account/keysets":
			plaintext = []byte(`{"keysets":[` + string(nativeTestKeysetJSON(t, keysetID, "mp", muk, keysetKey)) + `]}`)
		case "/api/v1/objects/" + vaultID + "/access/combined":
			plaintext = []byte(`{"access":[` + string(nativeTestVaultAccessJSON(t, vaultID, keysetID, keysetKey, vaultKey)) + `]}`)
		case nativeItemBatchPath(vaultID):
			if r.Method != http.MethodPatch {
				t.Fatalf("got method %q, want PATCH", r.Method)
			}
			var sealed nativeEncryptedMessage
			if err := json.NewDecoder(r.Body).Decode(&sealed); err != nil {
				t.Fatal(err)
			}
			body, err := nativeOpenSessionPayload(sessionKey, sealed)
			if err != nil {
				t.Fatal(err)
			}
			var request nativePatchVaultItemsRequest
			if err := json.Unmarshal(body, &request); err != nil {
				t.Fatal(err)
			}
			if request.ContentVersion != 42 || len(request.Items) == 0 {
				t.Fatalf("unexpected patch request: %+v", request)
			}
			for _, item := range request.Items {
				if item.UUID == "" {
					t.Fatalf("unexpected patch request item: %+v", item)
				}
			}
			response := nativePatchVaultItemsResponse{
				ContentVersion: 43,
				UpdatedItems:   request.Items,
			}
			if len(response.UpdatedItems) > 1 {
				for left, right := 0, len(response.UpdatedItems)-1; left < right; left, right = left+1, right-1 {
					response.UpdatedItems[left], response.UpdatedItems[right] = response.UpdatedItems[right], response.UpdatedItems[left]
				}
			}
			encoded, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			plaintext = encoded
		default:
			t.Fatalf("unexpected path %q", r.URL.String())
		}
		response, err := nativeSealSessionPayload("session-id", sessionKey, []byte("123456789012"), plaintext)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Fatal(err)
		}
	}))
}

func nativeTestEncryptedItemJSON(t *testing.T, vaultID string, vaultKey []byte, includeDetails bool) []byte {
	t.Helper()
	item := nativeEncryptedItemData{
		UUID:        "abcdefghijklmnopqrstuvwx56",
		Type:        "API_CREDENTIAL",
		ItemVersion: 2,
		EncryptedBy: vaultID,
		VaultKeySN:  1,
		CreatedAt:   json.RawMessage(`"2026-07-04T00:00:00Z"`),
		UpdatedAt:   json.RawMessage(`"2026-07-04T01:00:00Z"`),
		EncOverview: nativeTestEncryptedJWK(t, vaultID, vaultKey, []byte("345678901234"), []byte(`{
			"title":"keyring",
			"category":"API_CREDENTIAL",
			"tags":["keyring-1password"],
			"state":"active"
		}`)),
	}
	if includeDetails {
		item.EncDetails = nativeTestEncryptedJWK(t, vaultID, vaultKey, []byte("456789012345"), []byte(`{
			"fields":[
				{"id":"username","title":"username","fieldType":"Text","value":"provider-key"},
				{"id":"credential","title":"credential","fieldType":"Concealed","value":"dmFsdWU="}
			],
			"sections":[]
		}`))
	}
	body, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestNativeDecodeItemRejectsPlaintextItems(t *testing.T) {
	sessionKey := []byte("12345678901234567890123456789012")
	muk := []byte("abcdefghijklmnopqrstuvwx12345678")
	keysetID := "abcdefghijklmnopqrstuvwx90"
	keysetKey := []byte("23456789012345678901234567890123")
	vaultID := "abcdefghijklmnopqrstuvwx12"
	vaultKey := []byte("34567890123456789012345678901234")
	server := nativeEncryptedItemServer(t, sessionKey, muk, keysetID, keysetKey, vaultID, vaultKey, map[string][]byte{
		"/api/v1/vault/abcdefghijklmnopqrstuvwx12/item/abcdefghijklmnopqrstuvwx34": []byte(`{
			"id":"abcdefghijklmnopqrstuvwx34",
			"title":"keyring",
			"category":"API_CREDENTIAL",
			"vaultId":"abcdefghijklmnopqrstuvwx12",
			"fields":[{"id":"credential","title":"credential","value":"forged"}]
		}`),
		"/api/v1/vault/abcdefghijklmnopqrstuvwx12/items/overviews": []byte(`[{
			"id":"abcdefghijklmnopqrstuvwx34",
			"title":"keyring",
			"category":"API_CREDENTIAL",
			"state":"active"
		}]`),
	})
	defer server.Close()

	client := nativeHTTPTestClient(t, server, sessionKey)
	client.keys = serviceAccountKeyMaterial{MUK: muk}
	if _, err := client.getItem(context.Background(), nativeVaultItemParams{
		VaultID: vaultID,
		ItemID:  "abcdefghijklmnopqrstuvwx34",
	}); err == nil {
		t.Fatal("expected plaintext item to be rejected")
	}
	if _, err := client.listItems(context.Background(), nativeItemsListParams{
		VaultID: vaultID,
	}); err == nil {
		t.Fatal("expected plaintext item overviews to be rejected")
	}
}

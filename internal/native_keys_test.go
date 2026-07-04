package internal

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNativeGetKeysetsUsesAccountRoute(t *testing.T) {
	sessionKey := []byte("12345678901234567890123456789012")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Method, http.MethodGet; got != want {
			t.Fatalf("got method %q, want %q", got, want)
		}
		if got, want := r.URL.String(), "/api/v2/account/keysets"; got != want {
			t.Fatalf("got path %q, want %q", got, want)
		}
		response, err := nativeSealSessionPayload("session-id", sessionKey, []byte("123456789012"), []byte(`{
			"keysets":[{
				"uuid":"abcdefghijklmnopqrstuvwx12",
				"encryptedBy":"mp",
				"sn":1,
				"encSymKey":{"kid":"mp","alg":"PBES2g-HS256","enc":"A256GCM","cty":"b5+jwk+json","iv":"aXY","data":"ZGF0YQ","p2c":100000,"p2s":"c2FsdA"},
				"encPriKey":{"kid":"abcdefghijklmnopqrstuvwx12","enc":"A256GCM","cty":"b5+jwk+json","iv":"aXY","data":"ZGF0YQ"},
				"pubKey":{"kty":"RSA"}
			}]
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
	response, err := client.getKeysets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Keysets) != 1 || response.Keysets[0].EncryptedBy != "mp" {
		t.Fatalf("unexpected keysets response: %+v", response)
	}
	if response.Keysets[0].EncSymKey.P2C != 100000 {
		t.Fatalf("unexpected encSymKey: %+v", response.Keysets[0].EncSymKey)
	}
}

func TestNativeGetCombinedAccessUsesAccountRoute(t *testing.T) {
	sessionKey := []byte("12345678901234567890123456789012")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Method, http.MethodGet; got != want {
			t.Fatalf("got method %q, want %q", got, want)
		}
		if got, want := r.URL.String(), "/api/v1/objects/abcdefghijklmnopqrstuvwx12/access/combined"; got != want {
			t.Fatalf("got path %q, want %q", got, want)
		}
		response, err := nativeSealSessionPayload("session-id", sessionKey, []byte("123456789012"), []byte(`{
			"access":[{
				"vaultUuid":"abcdefghijklmnopqrstuvwx12",
				"accessorType":"user",
				"accessorUuid":"abcdefghijklmnopqrstuvwx34",
				"accessVersion":1,
				"acl":7,
				"leaseTimeout":0,
				"vaultKeySN":1,
				"encryptedBy":"abcdefghijklmnopqrstuvwx34",
				"encVaultKey":{"kid":"abcdefghijklmnopqrstuvwx34","enc":"A256GCM","cty":"b5+jwk+json","iv":"aXY","data":"ZGF0YQ"}
			}]
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
	response, err := client.getCombinedAccess(context.Background(), "abcdefghijklmnopqrstuvwx12")
	if err != nil {
		t.Fatal(err)
	}
	if len(response.VaultAccess) != 1 || response.VaultAccess[0].VaultKeySN != 1 {
		t.Fatalf("unexpected access response: %+v", response)
	}
}

func TestNativeCombinedAccessAcceptsBareArray(t *testing.T) {
	var response nativeCombinedAccessResponse
	if err := json.Unmarshal([]byte(`[{"vaultUuid":"abcdefghijklmnopqrstuvwx12"}]`), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.VaultAccess) != 1 || response.VaultAccess[0].VaultUUID != "abcdefghijklmnopqrstuvwx12" {
		t.Fatalf("unexpected access response: %+v", response)
	}
}

func TestNativeSymmetricKeyDecryptJWK(t *testing.T) {
	key := nativeSymmetricKey{ID: "mp", Key: []byte("12345678901234567890123456789012")}
	plaintext := nativeTestSymmetricJWK(t, "abcdefghijklmnopqrstuvwx12", []byte("abcdefghijklmnopqrstuvwx12345678"))
	encrypted := nativeTestEncryptedJWK(t, "mp", key.Key, []byte("123456789012"), plaintext)

	got, err := key.decryptJWK(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("got %s, want %s", got, plaintext)
	}

	encrypted.KeyID = "other"
	if _, err := key.decryptJWK(encrypted); err == nil {
		t.Fatal("expected kid mismatch")
	}
}

func TestNativeSymmetricKeyEncryptJWKRoundTrip(t *testing.T) {
	key := nativeSymmetricKey{ID: "mp", Key: []byte("12345678901234567890123456789012")}
	plaintext := nativeTestSymmetricJWK(t, "abcdefghijklmnopqrstuvwx12", []byte("abcdefghijklmnopqrstuvwx12345678"))

	encrypted, err := key.encryptJWKWithIV(plaintext, []byte("123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	if encrypted.KeyID != "mp" || encrypted.Encryption != "A256GCM" || encrypted.ContentType != "b5+jwk+json" {
		t.Fatalf("unexpected encrypted JWK envelope: %+v", encrypted)
	}

	got, err := key.decryptJWK(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("got %s, want %s", got, plaintext)
	}
}

func TestNativeClientUnlocksVaultKeys(t *testing.T) {
	sessionKey := []byte("12345678901234567890123456789012")
	muk := []byte("abcdefghijklmnopqrstuvwx12345678")
	keysetID := "abcdefghijklmnopqrstuvwx34"
	keysetKey := []byte("23456789012345678901234567890123")
	vaultID := "abcdefghijklmnopqrstuvwx12"
	vaultKey := []byte("34567890123456789012345678901234")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var plaintext []byte
		switch r.URL.String() {
		case "/api/v2/account/keysets":
			plaintext = []byte(`{"keysets":[` + string(nativeTestKeysetJSON(t, keysetID, "mp", muk, keysetKey)) + `]}`)
		case "/api/v1/objects/abcdefghijklmnopqrstuvwx12/access/combined":
			plaintext = []byte(`{"access":[` + string(nativeTestVaultAccessJSON(t, vaultID, keysetID, keysetKey, vaultKey)) + `]}`)
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
	keys, err := client.unlockedVaultKeys(context.Background(), vaultID)
	if err != nil {
		t.Fatal(err)
	}
	got := keys[1]
	if got.ID != vaultID || !bytes.Equal(got.Key, vaultKey) {
		t.Fatalf("unexpected vault key: %+v", got)
	}
}

func TestNativeLatestVaultKeySelectsHighestSerial(t *testing.T) {
	keys := map[int]nativeSymmetricKey{
		1: {ID: "old", Key: []byte("12345678901234567890123456789012")},
		3: {ID: "new", Key: []byte("34567890123456789012345678901234")},
		2: {ID: "middle", Key: []byte("23456789012345678901234567890123")},
	}

	sn, key, err := nativeLatestVaultKey(keys)
	if err != nil {
		t.Fatal(err)
	}
	if sn != 3 || key.ID != "new" {
		t.Fatalf("got serial %d key %+v, want serial 3 key new", sn, key)
	}

	if _, _, err := nativeLatestVaultKey(nil); err == nil {
		t.Fatal("expected empty vault key error")
	}
}

func nativeTestKeysetJSON(t *testing.T, keysetID, encryptedBy string, parentKey, keysetKey []byte) []byte {
	t.Helper()
	body, err := json.Marshal(nativeKeyset{
		UUID:        keysetID,
		EncryptedBy: encryptedBy,
		SN:          1,
		EncSymKey:   nativeTestEncryptedJWK(t, encryptedBy, parentKey, []byte("123456789012"), nativeTestSymmetricJWK(t, keysetID, keysetKey)),
		PubKey:      json.RawMessage(`{"kty":"RSA"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func nativeTestVaultAccessJSON(t *testing.T, vaultID, encryptedBy string, parentKey, vaultKey []byte) []byte {
	t.Helper()
	body, err := json.Marshal(nativeVaultAccessRecord{
		VaultUUID:    vaultID,
		AccessorType: "user",
		AccessorUUID: encryptedBy,
		VaultKeySN:   1,
		EncryptedBy:  encryptedBy,
		EncVaultKey:  nativeTestEncryptedJWK(t, encryptedBy, parentKey, []byte("234567890123"), nativeTestSymmetricJWK(t, vaultID, vaultKey)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func nativeTestSymmetricJWK(t *testing.T, id string, key []byte) []byte {
	t.Helper()
	body, err := json.Marshal(struct {
		KeyID     string   `json:"kid"`
		KeyType   string   `json:"kty"`
		Algorithm string   `json:"alg"`
		Key       string   `json:"k"`
		KeyOps    []string `json:"key_ops"`
	}{
		KeyID:     id,
		KeyType:   "oct",
		Algorithm: "A256GCM",
		Key:       base64.RawURLEncoding.EncodeToString(key),
		KeyOps:    []string{"encrypt", "decrypt"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func nativeTestEncryptedJWK(t *testing.T, keyID string, key, iv, plaintext []byte) nativeEncryptedJWK {
	t.Helper()
	message, err := nativeSealSessionPayload(keyID, key, iv, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return nativeEncryptedJWK{
		KeyID:       message.KeyID,
		Encryption:  message.Encryption,
		ContentType: message.ContentType,
		IV:          message.IV,
		Data:        message.Data,
	}
}

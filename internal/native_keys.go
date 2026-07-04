package internal

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

type nativeKeysetsResponse struct {
	Keysets []nativeKeyset `json:"keysets"`
}

type nativeKeyset struct {
	UUID        string             `json:"uuid"`
	EncryptedBy string             `json:"encryptedBy"`
	SN          int                `json:"sn"`
	EncPriKey   nativeEncryptedJWK `json:"encPriKey"`
	EncSymKey   nativeEncryptedJWK `json:"encSymKey"`
	PubKey      json.RawMessage    `json:"pubKey"`
	EncSPriKey  json.RawMessage    `json:"encSPriKey,omitempty"`
	SPubKey     json.RawMessage    `json:"spubKey,omitempty"`
}

type nativeEncryptedJWK struct {
	KeyID       string `json:"kid,omitempty"`
	Algorithm   string `json:"alg,omitempty"`
	Encryption  string `json:"enc,omitempty"`
	ContentType string `json:"cty,omitempty"`
	IV          string `json:"iv,omitempty"`
	Data        string `json:"data"`
	P2C         uint32 `json:"p2c,omitempty"`
	P2S         string `json:"p2s,omitempty"`
}

type nativeCombinedAccessResponse struct {
	VaultAccess []nativeVaultAccessRecord `json:"access"`
}

func (r *nativeCombinedAccessResponse) UnmarshalJSON(data []byte) error {
	var records []nativeVaultAccessRecord
	if err := json.Unmarshal(data, &records); err == nil {
		r.VaultAccess = records
		return nil
	}
	var object struct {
		Access      []nativeVaultAccessRecord `json:"access"`
		VaultAccess []nativeVaultAccessRecord `json:"vaultAccess"`
	}
	if err := json.Unmarshal(data, &object); err != nil {
		return err
	}
	if object.Access != nil {
		r.VaultAccess = object.Access
		return nil
	}
	r.VaultAccess = object.VaultAccess
	return nil
}

type nativeVaultAccessRecord struct {
	VaultUUID     string             `json:"vaultUuid"`
	AccessorType  string             `json:"accessorType"`
	AccessorUUID  string             `json:"accessorUuid"`
	AccessVersion uint32             `json:"accessVersion,omitempty"`
	ACL           uint64             `json:"acl,omitempty"`
	LeaseTimeout  uint32             `json:"leaseTimeout"`
	VaultKeySN    int                `json:"vaultKeySN"`
	EncryptedBy   string             `json:"encryptedBy"`
	EncVaultKey   nativeEncryptedJWK `json:"encVaultKey"`
}

type nativeSymmetricKey struct {
	ID  string
	Key []byte
}

func (k nativeSymmetricKey) decryptJWK(jwk nativeEncryptedJWK) ([]byte, error) {
	if jwk.KeyID != "" && jwk.KeyID != k.ID {
		return nil, fmt.Errorf("encrypted JWK kid %q does not match key %q", jwk.KeyID, k.ID)
	}
	if jwk.Encryption != "A256GCM" {
		return nil, fmt.Errorf("unsupported encrypted JWK enc %q", jwk.Encryption)
	}
	if jwk.ContentType != "b5+jwk+json" {
		return nil, fmt.Errorf("unsupported encrypted JWK cty %q", jwk.ContentType)
	}
	iv, err := decodeTokenPayload(jwk.IV)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted JWK iv: %w", err)
	}
	ciphertext, err := decodeTokenPayload(jwk.Data)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted JWK data: %w", err)
	}
	return aes256GCMOpen(k.Key, iv, ciphertext, nil)
}

func (k nativeSymmetricKey) encryptJWK(plaintext []byte) (nativeEncryptedJWK, error) {
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return nativeEncryptedJWK{}, fmt.Errorf("generate encrypted JWK iv: %w", err)
	}
	return k.encryptJWKWithIV(plaintext, iv)
}

func (k nativeSymmetricKey) encryptJWKWithIV(plaintext, iv []byte) (nativeEncryptedJWK, error) {
	if k.ID == "" {
		return nativeEncryptedJWK{}, fmt.Errorf("encrypted JWK key id is required")
	}
	ciphertext, err := aes256GCMSeal(k.Key, iv, plaintext, nil)
	if err != nil {
		return nativeEncryptedJWK{}, err
	}
	return nativeEncryptedJWK{
		KeyID:       k.ID,
		Encryption:  "A256GCM",
		ContentType: "b5+jwk+json",
		IV:          base64.RawURLEncoding.EncodeToString(iv),
		Data:        base64.RawURLEncoding.EncodeToString(ciphertext),
	}, nil
}

func nativeSymmetricKeyFromJWK(data []byte) (nativeSymmetricKey, error) {
	var jwk struct {
		KeyID     string   `json:"kid"`
		KeyType   string   `json:"kty"`
		Algorithm string   `json:"alg"`
		Key       string   `json:"k"`
		KeyOps    []string `json:"key_ops"`
	}
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nativeSymmetricKey{}, fmt.Errorf("decode symmetric JWK: %w", err)
	}
	if jwk.KeyType != "oct" {
		return nativeSymmetricKey{}, fmt.Errorf("unsupported symmetric JWK kty %q", jwk.KeyType)
	}
	if jwk.Algorithm != "" && jwk.Algorithm != "A256GCM" {
		return nativeSymmetricKey{}, fmt.Errorf("unsupported symmetric JWK alg %q", jwk.Algorithm)
	}
	if jwk.KeyID == "" {
		return nativeSymmetricKey{}, fmt.Errorf("symmetric JWK is missing kid")
	}
	key, err := decodeTokenPayload(jwk.Key)
	if err != nil {
		return nativeSymmetricKey{}, fmt.Errorf("decode symmetric JWK key: %w", err)
	}
	if len(key) != 32 {
		return nativeSymmetricKey{}, fmt.Errorf("symmetric JWK key must be 32 bytes")
	}
	return nativeSymmetricKey{ID: jwk.KeyID, Key: key}, nil
}

func (c *nativeClient) unlockedKeysets(ctx context.Context) (map[string]nativeSymmetricKey, error) {
	response, err := c.getKeysets(ctx)
	if err != nil {
		return nil, err
	}
	keys := map[string]nativeSymmetricKey{
		"mp": {ID: "mp", Key: c.keys.MUK},
	}
	for _, keyset := range response.Keysets {
		unlockingKey, ok := keys[keyset.EncryptedBy]
		if !ok {
			return nil, fmt.Errorf("keyset %q is encrypted by unknown key %q", keyset.UUID, keyset.EncryptedBy)
		}
		plaintext, err := unlockingKey.decryptJWK(keyset.EncSymKey)
		if err != nil {
			return nil, err
		}
		key, err := nativeSymmetricKeyFromJWK(plaintext)
		if err != nil {
			return nil, err
		}
		if key.ID != keyset.UUID {
			return nil, fmt.Errorf("keyset %q decrypted to key %q", keyset.UUID, key.ID)
		}
		keys[key.ID] = key
	}
	return keys, nil
}

func (c *nativeClient) unlockedVaultKeys(ctx context.Context, vaultID string) (map[int]nativeSymmetricKey, error) {
	keysets, err := c.unlockedKeysets(ctx)
	if err != nil {
		return nil, err
	}
	access, err := c.getCombinedAccess(ctx, vaultID)
	if err != nil {
		return nil, err
	}
	vaultKeys := map[int]nativeSymmetricKey{}
	for _, record := range access.VaultAccess {
		if record.VaultUUID != vaultID {
			continue
		}
		unlockingKey, ok := keysets[record.EncryptedBy]
		if !ok {
			return nil, fmt.Errorf("vault key for %q is encrypted by unknown key %q", vaultID, record.EncryptedBy)
		}
		plaintext, err := unlockingKey.decryptJWK(record.EncVaultKey)
		if err != nil {
			return nil, err
		}
		key, err := nativeSymmetricKeyFromJWK(plaintext)
		if err != nil {
			return nil, err
		}
		vaultKeys[record.VaultKeySN] = key
	}
	if len(vaultKeys) == 0 {
		return nil, fmt.Errorf("no vault keys found for %q", vaultID)
	}
	return vaultKeys, nil
}

func nativeLatestVaultKey(vaultKeys map[int]nativeSymmetricKey) (int, nativeSymmetricKey, error) {
	if len(vaultKeys) == 0 {
		return 0, nativeSymmetricKey{}, fmt.Errorf("no vault keys found")
	}
	latestSN := 0
	for sn := range vaultKeys {
		if sn > latestSN {
			latestSN = sn
		}
	}
	return latestSN, vaultKeys[latestSN], nil
}

func (c *nativeClient) getKeysets(ctx context.Context) (nativeKeysetsResponse, error) {
	if err := c.ensureSession(ctx); err != nil {
		return nativeKeysetsResponse{}, err
	}
	var response nativeKeysetsResponse
	if err := c.doNativeJSON(ctx, http.MethodGet, "/api/v2/account/keysets", nil, &response); err != nil {
		return nativeKeysetsResponse{}, err
	}
	if len(response.Keysets) == 0 {
		return nativeKeysetsResponse{}, fmt.Errorf("keysets response is empty")
	}
	return response, nil
}

func (c *nativeClient) getCombinedAccess(ctx context.Context, vaultID string) (nativeCombinedAccessResponse, error) {
	if err := validateNativeObjectID("vault_id", vaultID); err != nil {
		return nativeCombinedAccessResponse{}, err
	}
	if err := c.ensureSession(ctx); err != nil {
		return nativeCombinedAccessResponse{}, err
	}
	var response nativeCombinedAccessResponse
	if err := c.doNativeJSON(ctx, http.MethodGet, "/api/v1/objects/"+url.PathEscape(vaultID)+"/access/combined", nil, &response); err != nil {
		return nativeCombinedAccessResponse{}, err
	}
	return response, nil
}

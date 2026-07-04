package internal

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
)

type serviceAccountCredentials struct {
	SignInAddress  string                       `json:"signInAddress"`
	Email          string                       `json:"email"`
	SecretKey      string                       `json:"secretKey"`
	SRPX           string                       `json:"srpX"`
	MUK            serviceAccountJWK            `json:"muk"`
	UserAuth       serviceAccountUserAuth       `json:"userAuth"`
	DeviceUUID     string                       `json:"deviceUuid"`
	ThrottleSecret serviceAccountThrottleSecret `json:"throttleSecret"`
}

type serviceAccountJWK struct {
	Alg    string   `json:"alg"`
	Ext    bool     `json:"ext"`
	K      string   `json:"k"`
	KeyOps []string `json:"key_ops"`
	Kty    string   `json:"kty"`
	KID    string   `json:"kid"`
}

type serviceAccountUserAuth struct {
	Alg        string `json:"alg"`
	Iterations uint32 `json:"iterations"`
	Method     string `json:"method"`
	Salt       string `json:"salt"`
}

type serviceAccountThrottleSecret struct {
	Seed string `json:"seed"`
	UUID string `json:"uuid"`
}

type serviceAccountKeyMaterial struct {
	MUK            []byte
	SRPX           []byte
	UserAuthSalt   []byte
	ThrottleSecret []byte
}

type serviceAccountSecretKeyInfo struct {
	Format string
	ID     string
}

type nativeAuthStartRequest struct {
	Email      string `json:"email"`
	SKFormat   string `json:"skFormat"`
	SKID       string `json:"skid"`
	DeviceUUID string `json:"deviceUuid"`
}

type nativeAuthStartResponse struct {
	Status           string                 `json:"status"`
	SessionID        string                 `json:"sessionID"`
	AccountKeyFormat string                 `json:"accountKeyFormat"`
	AccountKeyUUID   string                 `json:"accountKeyUuid"`
	UserAuth         serviceAccountUserAuth `json:"userAuth"`
}

type nativeAuthRequest struct {
	SessionID string `json:"-"`
	UserA     string `json:"userA"`
}

type nativeAuthResponse struct {
	SessionID        string `json:"sessionID,omitempty"`
	UserB            string `json:"userB"`
	ServerVerifyHash string `json:"serverVerifyHash"`
}

type nativeAuthVerifyRequest struct {
	ClientVerifyHash string `json:"clientVerifyHash"`
}

type nativeSRPCompletion struct {
	SessionKey  []byte
	ClientProof []byte
}

func parseServiceAccountToken(token string) (serviceAccountCredentials, error) {
	payload, ok := strings.CutPrefix(strings.TrimSpace(token), "ops_")
	if !ok || payload == "" {
		return serviceAccountCredentials{}, errors.New("service account token must start with ops_")
	}

	decoded, err := decodeTokenPayload(payload)
	if err != nil {
		return serviceAccountCredentials{}, fmt.Errorf("decode service account token: %w", err)
	}

	var creds serviceAccountCredentials
	if err := json.Unmarshal(decoded, &creds); err != nil {
		return serviceAccountCredentials{}, fmt.Errorf("parse service account token: %w", err)
	}
	if err := creds.validate(); err != nil {
		return serviceAccountCredentials{}, err
	}
	return creds, nil
}

func decodeTokenPayload(payload string) ([]byte, error) {
	encodings := []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	}
	var lastErr error
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(payload)
		if err == nil {
			return decoded, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (c serviceAccountCredentials) validate() error {
	missing := []string{}
	if strings.TrimSpace(c.SignInAddress) == "" {
		missing = append(missing, "signInAddress")
	}
	if strings.TrimSpace(c.Email) == "" {
		missing = append(missing, "email")
	}
	if strings.TrimSpace(c.SecretKey) == "" {
		missing = append(missing, "secretKey")
	}
	if strings.TrimSpace(c.SRPX) == "" {
		missing = append(missing, "srpX")
	}
	if c.MUK.empty() {
		missing = append(missing, "muk")
	}
	if c.UserAuth.empty() {
		missing = append(missing, "userAuth")
	}
	if !c.UserAuth.empty() {
		if err := c.UserAuth.validate(); err != nil {
			return err
		}
	}
	if strings.TrimSpace(c.DeviceUUID) == "" {
		missing = append(missing, "deviceUuid")
	}
	if c.ThrottleSecret.empty() {
		missing = append(missing, "throttleSecret")
	}
	if len(missing) > 0 {
		return fmt.Errorf("service account token is missing %s", strings.Join(missing, ", "))
	}
	if err := validateServiceAccountSecretKey(c.SecretKey); err != nil {
		return err
	}
	if err := validateNativeObjectID("deviceUuid", c.DeviceUUID); err != nil {
		return err
	}
	if err := validateNativeObjectID("throttleSecret.uuid", c.ThrottleSecret.UUID); err != nil {
		return err
	}
	if _, err := c.srpX(); err != nil {
		return err
	}
	return nil
}

func validateServiceAccountSecretKey(secretKey string) error {
	_, err := serviceAccountSecretKeyDetails(secretKey)
	return err
}

func serviceAccountSecretKeyDetails(secretKey string) (serviceAccountSecretKeyInfo, error) {
	parts := strings.Split(secretKey, "-")
	if len(parts) != 7 {
		return serviceAccountSecretKeyInfo{}, fmt.Errorf("secretKey must have format A3-XXXXXX-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX")
	}
	lengths := []int{2, 6, 6, 5, 5, 5, 5}
	for i, part := range parts {
		if len(part) != lengths[i] {
			return serviceAccountSecretKeyInfo{}, fmt.Errorf("secretKey must have format A3-XXXXXX-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX")
		}
		for _, r := range part {
			if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
				continue
			}
			return serviceAccountSecretKeyInfo{}, fmt.Errorf("secretKey must contain only uppercase letters, digits, and hyphens")
		}
	}
	if parts[0] != "A3" {
		return serviceAccountSecretKeyInfo{}, fmt.Errorf("unsupported secretKey version %q", parts[0])
	}
	return serviceAccountSecretKeyInfo{Format: parts[0], ID: parts[1]}, nil
}

func (c serviceAccountCredentials) authStartRequest() (nativeAuthStartRequest, error) {
	key, err := serviceAccountSecretKeyDetails(c.SecretKey)
	if err != nil {
		return nativeAuthStartRequest{}, err
	}
	return nativeAuthStartRequest{
		Email:      c.Email,
		SKFormat:   key.Format,
		SKID:       key.ID,
		DeviceUUID: c.DeviceUUID,
	}, nil
}

func (c *nativeClient) startAuth(ctx context.Context) (nativeAuthStartResponse, error) {
	request, err := c.creds.authStartRequest()
	if err != nil {
		return nativeAuthStartResponse{}, err
	}
	var response nativeAuthStartResponse
	if err := c.doNativeJSON(ctx, http.MethodPost, "/api/v3/auth/start", request, &response); err != nil {
		return nativeAuthStartResponse{}, err
	}
	if response.Status != "ok" {
		return nativeAuthStartResponse{}, fmt.Errorf("unexpected auth start status %q", response.Status)
	}
	if response.SessionID == "" {
		return nativeAuthStartResponse{}, fmt.Errorf("auth start response is missing sessionID")
	}
	if response.AccountKeyFormat != request.SKFormat {
		return nativeAuthStartResponse{}, fmt.Errorf("auth start accountKeyFormat mismatch")
	}
	if response.AccountKeyUUID != request.SKID {
		return nativeAuthStartResponse{}, fmt.Errorf("auth start accountKeyUuid mismatch")
	}
	if err := response.UserAuth.validate(); err != nil {
		return nativeAuthStartResponse{}, fmt.Errorf("auth start userAuth: %w", err)
	}
	return response, nil
}

func (r nativeAuthStartResponse) authRequest(userA string) (nativeAuthRequest, error) {
	if strings.TrimSpace(r.SessionID) == "" {
		return nativeAuthRequest{}, fmt.Errorf("auth response is missing sessionID")
	}
	if strings.TrimSpace(userA) == "" {
		return nativeAuthRequest{}, fmt.Errorf("auth request is missing userA")
	}
	return nativeAuthRequest{
		SessionID: r.SessionID,
		UserA:     userA,
	}, nil
}

func (r nativeAuthStartResponse) srpAuthRequest(ephemeralPrivate *big.Int) (nativeAuthRequest, error) {
	if _, err := nativeSRPMultiplier(r.SessionID); err != nil {
		return nativeAuthRequest{}, err
	}
	userA, err := nativeSRPClientPublicHex(ephemeralPrivate)
	if err != nil {
		return nativeAuthRequest{}, err
	}
	return r.authRequest(userA)
}

func (r nativeAuthStartResponse) generatedSRPAuthRequest() (nativeAuthRequest, *big.Int, error) {
	ephemeralPrivate, err := nativeSRPGenerateEphemeralPrivate()
	if err != nil {
		return nativeAuthRequest{}, nil, err
	}
	request, err := r.srpAuthRequest(ephemeralPrivate)
	if err != nil {
		return nativeAuthRequest{}, nil, err
	}
	return request, ephemeralPrivate, nil
}

func (c *nativeClient) ensureSession(ctx context.Context) error {
	if c.session != nil {
		return nil
	}

	// ponytail: one auth flow per client; split the lock if concurrent first-use ever matters.
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session != nil {
		return nil
	}

	start, err := c.startAuth(ctx)
	if err != nil {
		return err
	}
	authRequest, ephemeralPrivate, err := start.generatedSRPAuthRequest()
	if err != nil {
		return err
	}
	authResponse, err := c.authExchange(ctx, authRequest)
	if err != nil {
		return err
	}
	serverB, err := authResponse.serverPublic()
	if err != nil {
		return err
	}
	serverProof, err := authResponse.serverProof()
	if err != nil {
		return err
	}
	completion, err := start.completeSRP(c.keys, c.creds.Email, ephemeralPrivate, serverB, serverProof)
	if err != nil {
		return err
	}
	return c.verifyAuth(ctx, start.SessionID, completion)
}

func (c *nativeClient) authExchange(ctx context.Context, request nativeAuthRequest) (nativeAuthResponse, error) {
	var response nativeAuthResponse
	if err := c.doNativeJSON(ctx, http.MethodPost, "/api/v2/auth", request, &response); err != nil {
		return nativeAuthResponse{}, err
	}
	if response.SessionID != "" && response.SessionID != request.SessionID {
		return nativeAuthResponse{}, fmt.Errorf("auth response sessionID mismatch")
	}
	if strings.TrimSpace(response.UserB) == "" {
		return nativeAuthResponse{}, fmt.Errorf("auth response is missing userB")
	}
	if strings.TrimSpace(response.ServerVerifyHash) == "" {
		return nativeAuthResponse{}, fmt.Errorf("auth response is missing serverVerifyHash")
	}
	return response, nil
}

func (r nativeAuthResponse) serverPublic() (*big.Int, error) {
	if strings.TrimSpace(r.UserB) == "" {
		return nil, fmt.Errorf("auth response is missing userB")
	}
	serverB, ok := new(big.Int).SetString(r.UserB, 16)
	if !ok || !nativeSRPIsPublicValid(serverB) {
		return nil, fmt.Errorf("invalid auth response userB")
	}
	return serverB, nil
}

func (r nativeAuthResponse) serverProof() ([]byte, error) {
	if strings.TrimSpace(r.ServerVerifyHash) == "" {
		return nil, fmt.Errorf("auth response is missing serverVerifyHash")
	}
	proof, err := decodeTokenPayload(r.ServerVerifyHash)
	if err != nil {
		return nil, fmt.Errorf("decode serverVerifyHash: %w", err)
	}
	return proof, nil
}

func (r nativeAuthStartResponse) completeSRP(keys serviceAccountKeyMaterial, email string, ephemeralPrivate, serverB *big.Int, serverProof []byte) (nativeSRPCompletion, error) {
	x := new(big.Int).SetBytes(keys.SRPX)
	k, err := nativeSRPMultiplier(r.SessionID)
	if err != nil {
		return nativeSRPCompletion{}, err
	}
	clientA, err := nativeSRPClientPublicA(ephemeralPrivate)
	if err != nil {
		return nativeSRPCompletion{}, err
	}
	u, err := nativeSRPClientU(clientA, serverB)
	if err != nil {
		return nativeSRPCompletion{}, err
	}
	sessionKey, err := nativeSRPClientRawKey(x, ephemeralPrivate, serverB, u, k)
	if err != nil {
		return nativeSRPCompletion{}, err
	}
	expectedServerProof, err := nativeSRPServerProof(keys.UserAuthSalt, email, clientA, serverB, sessionKey)
	if err != nil {
		return nativeSRPCompletion{}, err
	}
	if !equalBytes(expectedServerProof, serverProof) {
		return nativeSRPCompletion{}, fmt.Errorf("SRP server proof mismatch")
	}
	clientProof, err := nativeSRPClientProof(clientA, serverProof, sessionKey)
	if err != nil {
		return nativeSRPCompletion{}, err
	}
	return nativeSRPCompletion{SessionKey: sessionKey, ClientProof: clientProof}, nil
}

func (c *nativeClient) verifyAuth(ctx context.Context, sessionID string, completion nativeSRPCompletion) error {
	if strings.TrimSpace(sessionID) == "" {
		return fmt.Errorf("auth verify requires sessionID")
	}
	if len(completion.SessionKey) == 0 {
		return fmt.Errorf("auth verify requires session key")
	}
	if len(completion.ClientProof) == 0 {
		return fmt.Errorf("auth verify requires client proof")
	}
	if err := c.doNativeJSON(ctx, http.MethodPost, "/api/v2/auth/confirm-key", c.authVerifyRequest(completion.ClientProof), nil); err != nil {
		return err
	}
	c.session = &nativeSession{ID: sessionID, Key: completion.SessionKey}
	return nil
}

func (c *nativeClient) authVerifyRequest(clientProof []byte) nativeAuthVerifyRequest {
	return nativeAuthVerifyRequest{
		ClientVerifyHash: base64.RawURLEncoding.EncodeToString(clientProof),
	}
}

func nativeSRPMultiplier(sessionID string) (*big.Int, error) {
	if err := validateNativeObjectID("sessionID", sessionID); err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes([]byte(sessionID)), nil
}

func equalBytes(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func (c serviceAccountCredentials) srpX() ([]byte, error) {
	srpX, err := hex.DecodeString(c.SRPX)
	if err != nil {
		return nil, fmt.Errorf("decode srpX: %w", err)
	}
	if len(srpX) != 32 {
		return nil, fmt.Errorf("srpX must be 32 bytes")
	}
	return srpX, nil
}

func (j serviceAccountJWK) empty() bool {
	return strings.TrimSpace(j.Alg) == "" ||
		strings.TrimSpace(j.K) == "" ||
		strings.TrimSpace(j.Kty) == "" ||
		strings.TrimSpace(j.KID) == ""
}

func (j serviceAccountJWK) key() ([]byte, error) {
	if j.Alg != "A256GCM" {
		return nil, fmt.Errorf("unsupported muk alg %q", j.Alg)
	}
	if j.Kty != "oct" {
		return nil, fmt.Errorf("unsupported muk kty %q", j.Kty)
	}
	if j.KID != "mp" {
		return nil, fmt.Errorf("unsupported muk kid %q", j.KID)
	}
	if !j.hasKeyOp("encrypt") || !j.hasKeyOp("decrypt") {
		return nil, fmt.Errorf("muk key_ops must include encrypt and decrypt")
	}
	key, err := decodeTokenPayload(j.K)
	if err != nil {
		return nil, fmt.Errorf("decode muk key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("muk key must be 32 bytes")
	}
	return key, nil
}

func (j serviceAccountJWK) hasKeyOp(op string) bool {
	for _, keyOp := range j.KeyOps {
		if keyOp == op {
			return true
		}
	}
	return false
}

func (u serviceAccountUserAuth) empty() bool {
	return strings.TrimSpace(u.Alg) == "" ||
		u.Iterations == 0 ||
		strings.TrimSpace(u.Method) == "" ||
		strings.TrimSpace(u.Salt) == ""
}

func (u serviceAccountUserAuth) validate() error {
	if u.Alg != "PBES2g-HS256" {
		return fmt.Errorf("unsupported userAuth alg %q", u.Alg)
	}
	if u.Method != "SRPg-4096" {
		return fmt.Errorf("unsupported userAuth method %q", u.Method)
	}
	if _, err := decodeTokenPayload(u.Salt); err != nil {
		return fmt.Errorf("decode userAuth salt: %w", err)
	}
	return nil
}

func (u serviceAccountUserAuth) salt() ([]byte, error) {
	salt, err := decodeTokenPayload(u.Salt)
	if err != nil {
		return nil, fmt.Errorf("decode userAuth salt: %w", err)
	}
	return salt, nil
}

func (t serviceAccountThrottleSecret) empty() bool {
	return strings.TrimSpace(t.Seed) == "" ||
		strings.TrimSpace(t.UUID) == ""
}

func (t serviceAccountThrottleSecret) seed() ([]byte, error) {
	seed, err := hex.DecodeString(t.Seed)
	if err != nil {
		return nil, fmt.Errorf("decode throttleSecret seed: %w", err)
	}
	if len(seed) != 32 {
		return nil, fmt.Errorf("throttleSecret seed must be 32 bytes")
	}
	return seed, nil
}

func (c serviceAccountCredentials) keyMaterial() (serviceAccountKeyMaterial, error) {
	muk, err := c.MUK.key()
	if err != nil {
		return serviceAccountKeyMaterial{}, err
	}
	srpX, err := c.srpX()
	if err != nil {
		return serviceAccountKeyMaterial{}, err
	}
	salt, err := c.UserAuth.salt()
	if err != nil {
		return serviceAccountKeyMaterial{}, err
	}
	throttleSecret, err := c.ThrottleSecret.seed()
	if err != nil {
		return serviceAccountKeyMaterial{}, err
	}
	return serviceAccountKeyMaterial{
		MUK:            muk,
		SRPX:           srpX,
		UserAuthSalt:   salt,
		ThrottleSecret: throttleSecret,
	}, nil
}

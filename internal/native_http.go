package internal

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func (c *nativeClient) nativeAPIURL(requestPath string) (*url.URL, error) {
	if c.baseURL == nil {
		return nil, fmt.Errorf("native client base URL is not configured")
	}
	if !strings.HasPrefix(requestPath, "/") {
		return nil, fmt.Errorf("native API path must start with /")
	}

	rel, err := url.Parse(requestPath)
	if err != nil {
		return nil, fmt.Errorf("parse native API path: %w", err)
	}
	if rel.IsAbs() || rel.Host != "" || rel.User != nil {
		return nil, fmt.Errorf("native API path must be relative to the account host")
	}
	if rel.Fragment != "" {
		return nil, fmt.Errorf("native API path must not include a fragment")
	}
	for _, segment := range strings.Split(rel.Path, "/") {
		if segment == ".." {
			return nil, fmt.Errorf("native API path must not include .. segments")
		}
	}

	u := *c.baseURL
	u.Path = rel.Path
	u.RawPath = rel.RawPath
	u.RawQuery = rel.RawQuery
	u.Fragment = ""
	return &u, nil
}

func (c *nativeClient) nativeJSONRequest(ctx context.Context, method, requestPath string, body interface{}) (*http.Request, error) {
	if strings.TrimSpace(method) == "" {
		return nil, fmt.Errorf("native API method is required")
	}

	u, err := c.nativeAPIURL(requestPath)
	if err != nil {
		return nil, err
	}

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal native API request body: %w", err)
		}
		if c.session != nil {
			encoded, err = c.session.encryptPayload(encoded)
			if err != nil {
				return nil, err
			}
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		return nil, fmt.Errorf("create native API request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if err := c.signNativeRequest(req); err != nil {
		return nil, err
	}
	return req, nil
}

func (c *nativeClient) signNativeRequest(req *http.Request) error {
	if c.session == nil {
		return nil
	}
	c.session.NextRequestID++
	requestID := c.session.NextRequestID

	mac, err := nativeRequestMAC(c.session.ID, req.Method, req.URL, requestID, c.session.Key)
	if err != nil {
		return err
	}
	req.Header.Set("X-AgileBits-Session-ID", c.session.ID)
	req.Header.Set("X-AgileBits-MAC", mac)
	return nil
}

func nativeRequestMAC(sessionID, method string, requestURL *url.URL, requestID uint64, sessionKey []byte) (string, error) {
	if strings.TrimSpace(sessionID) == "" {
		return "", fmt.Errorf("native session id is required")
	}
	if strings.TrimSpace(method) == "" {
		return "", fmt.Errorf("native request method is required")
	}
	if requestURL == nil {
		return "", fmt.Errorf("native request URL is required")
	}
	if strings.TrimSpace(requestURL.Hostname()) == "" {
		return "", fmt.Errorf("native request host is required")
	}
	if len(sessionKey) == 0 {
		return "", fmt.Errorf("native session key is required")
	}

	const version = "v1"
	keyMAC := hmac.New(sha256.New, sessionKey)
	keyMAC.Write([]byte("He never wears a Mac, in the pouring rain. Very strange."))
	derivationKey := keyMAC.Sum(nil)

	macURL := strings.ToLower(requestURL.Hostname()) + "/" + strings.TrimLeft(requestURL.EscapedPath(), "/") + "?" + requestURL.RawQuery
	authString := fmt.Sprintf("%s|%s|%s|%s|%d", sessionID, strings.ToUpper(method), macURL, version, requestID)
	requestMAC := hmac.New(sha256.New, derivationKey)
	requestMAC.Write([]byte(authString))
	sum := requestMAC.Sum(nil)

	return fmt.Sprintf("%s|%d|%s", version, requestID, base64.RawURLEncoding.EncodeToString(sum[:12])), nil
}

func (c *nativeClient) doNativeJSON(ctx context.Context, method, requestPath string, requestBody, responseBody interface{}) error {
	hadSession := c.session != nil
	err := c.doNativeJSONOnce(ctx, method, requestPath, requestBody, responseBody)
	if err == nil || !hadSession || nativeErrorName(err) != "Unauthenticated" {
		return err
	}
	// The server-side session expired; drop it, re-authenticate, and retry once.
	c.invalidateSession()
	if err := c.ensureSession(ctx); err != nil {
		return err
	}
	return c.doNativeJSONOnce(ctx, method, requestPath, requestBody, responseBody)
}

func (c *nativeClient) doNativeJSONOnce(ctx context.Context, method, requestPath string, requestBody, responseBody interface{}) error {
	req, err := c.nativeJSONRequest(ctx, method, requestPath, requestBody)
	if err != nil {
		return err
	}

	client := c.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send native API request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nativeHTTPStatusError(resp.StatusCode)
	}
	if responseBody == nil {
		io.Copy(io.Discard, resp.Body)
		return nil
	}
	if c.session != nil {
		var encrypted nativeEncryptedMessage
		if err := json.NewDecoder(resp.Body).Decode(&encrypted); err != nil {
			return fmt.Errorf("decode native encrypted API response: %w", err)
		}
		plaintext, err := c.session.decryptPayload(encrypted)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(plaintext, responseBody); err != nil {
			return fmt.Errorf("decode native API response: %w", err)
		}
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(responseBody); err != nil {
		return fmt.Errorf("decode native API response: %w", err)
	}
	return nil
}

type nativeEncryptedMessage struct {
	KeyID       string `json:"kid"`
	Encryption  string `json:"enc"`
	ContentType string `json:"cty"`
	IV          string `json:"iv"`
	Data        string `json:"data"`
}

func (s *nativeSession) encryptPayload(plaintext []byte) ([]byte, error) {
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("generate native API payload iv: %w", err)
	}
	message, err := nativeSealSessionPayload(s.ID, s.Key, iv, plaintext)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("marshal native encrypted API request body: %w", err)
	}
	return encoded, nil
}

func (s *nativeSession) decryptPayload(message nativeEncryptedMessage) ([]byte, error) {
	return nativeOpenSessionPayload(s.Key, message)
}

func nativeSealSessionPayload(keyID string, sessionKey, iv, plaintext []byte) (nativeEncryptedMessage, error) {
	if strings.TrimSpace(keyID) == "" {
		return nativeEncryptedMessage{}, fmt.Errorf("native encrypted payload key id is required")
	}
	ciphertext, err := aes256GCMSeal(sessionKey, iv, plaintext, nil)
	if err != nil {
		return nativeEncryptedMessage{}, err
	}
	return nativeEncryptedMessage{
		KeyID:       keyID,
		Encryption:  "A256GCM",
		ContentType: "b5+jwk+json",
		IV:          base64.RawURLEncoding.EncodeToString(iv),
		Data:        base64.RawURLEncoding.EncodeToString(ciphertext),
	}, nil
}

func nativeOpenSessionPayload(sessionKey []byte, message nativeEncryptedMessage) ([]byte, error) {
	if message.Encryption != "A256GCM" {
		return nil, fmt.Errorf("unsupported native encrypted payload enc %q", message.Encryption)
	}
	if message.ContentType != "b5+jwk+json" {
		return nil, fmt.Errorf("unsupported native encrypted payload cty %q", message.ContentType)
	}
	iv, err := decodeTokenPayload(message.IV)
	if err != nil {
		return nil, fmt.Errorf("decode native encrypted payload iv: %w", err)
	}
	ciphertext, err := decodeTokenPayload(message.Data)
	if err != nil {
		return nil, fmt.Errorf("decode native encrypted payload data: %w", err)
	}
	return aes256GCMOpen(sessionKey, iv, ciphertext, nil)
}

func nativeHTTPStatusError(status int) error {
	switch status {
	case http.StatusBadRequest:
		return nativeError("InvalidUserInput", "bad request sent to the server")
	case http.StatusUnauthorized:
		return nativeError("Unauthenticated", "you are not authenticated")
	case http.StatusForbidden:
		return nativeError("PermissionDenied", "you don't have the right permissions to access this resource")
	case http.StatusNotFound:
		return nativeError("NotFound", "resource not found")
	case http.StatusConflict:
		return nativeError("Conflict", "a conflict occurred on the server")
	case http.StatusTooManyRequests:
		return nativeError("RateLimitExceeded", "rate limit exceeded")
	default:
		return nativeError("ServerError", fmt.Sprintf("native API request failed with status %d", status))
	}
}

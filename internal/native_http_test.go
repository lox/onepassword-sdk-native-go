package internal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestNativeAPIURLConfinesPathsToAccountHost(t *testing.T) {
	base, err := url.Parse("https://example.1password.com")
	if err != nil {
		t.Fatal(err)
	}
	client := &nativeClient{baseURL: base}

	u, err := client.nativeAPIURL("/api/v1/vaults?vault=one")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := u.String(), "https://example.1password.com/api/v1/vaults?vault=one"; got != want {
		t.Fatalf("got URL %q, want %q", got, want)
	}
}

func TestNativeAPIURLRejectsUnsafePaths(t *testing.T) {
	base, err := url.Parse("https://example.1password.com")
	if err != nil {
		t.Fatal(err)
	}
	client := &nativeClient{baseURL: base}

	for _, requestPath := range []string{
		"",
		"api/v1/vaults",
		"https://evil.example/vaults",
		"//evil.example/vaults",
		"/api/../vaults",
		"/api/vaults#fragment",
	} {
		t.Run(requestPath, func(t *testing.T) {
			if _, err := client.nativeAPIURL(requestPath); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestNativeJSONRequestEncodesJSON(t *testing.T) {
	base, err := url.Parse("https://example.1password.com")
	if err != nil {
		t.Fatal(err)
	}
	client := &nativeClient{baseURL: base}

	req, err := client.nativeJSONRequest(context.Background(), http.MethodPost, "/api", map[string]string{"name": "vault"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := req.Header.Get("Accept"), "application/json"; got != want {
		t.Fatalf("got Accept %q, want %q", got, want)
	}
	if got, want := req.Header.Get("Content-Type"), "application/json"; got != want {
		t.Fatalf("got Content-Type %q, want %q", got, want)
	}

	var body map[string]string
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if got, want := body["name"], "vault"; got != want {
		t.Fatalf("got body name %q, want %q", got, want)
	}
}

func TestNativeJSONRequestSignsWhenSessionExists(t *testing.T) {
	base, err := url.Parse("https://example.1password.com")
	if err != nil {
		t.Fatal(err)
	}
	client := &nativeClient{
		baseURL: base,
		session: &nativeSession{
			ID:  "session-id",
			Key: []byte("session key"),
		},
	}

	req, err := client.nativeJSONRequest(context.Background(), http.MethodGet, "/api/v1/vaults?attrs=combined-access", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := req.Header.Get("X-AgileBits-Session-Id"), "session-id"; got != want {
		t.Fatalf("got session header %q, want %q", got, want)
	}
	mac := req.Header.Get("X-AgileBits-MAC")
	if !strings.HasPrefix(mac, "v1|1|") {
		t.Fatalf("got MAC header %q, want v1 request 1", mac)
	}
	if len(strings.TrimPrefix(mac, "v1|1|")) != 16 {
		t.Fatalf("got MAC header %q, want 16 base64url chars for 12 bytes", mac)
	}
	if client.session.NextRequestID != 1 {
		t.Fatalf("got next request id %d, want 1", client.session.NextRequestID)
	}

	req, err = client.nativeJSONRequest(context.Background(), http.MethodGet, "/api/v1/vaults", nil)
	if err != nil {
		t.Fatal(err)
	}
	requestID, err := strconv.ParseUint(strings.Split(req.Header.Get("X-AgileBits-MAC"), "|")[1], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if requestID != 2 {
		t.Fatalf("got request id %d, want 2", requestID)
	}
}

func TestNativeRequestMACRejectsMissingInputs(t *testing.T) {
	u, err := url.Parse("https://example.1password.com/api")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		sessionID string
		method    string
		url       *url.URL
		key       []byte
	}{
		{name: "session", method: http.MethodGet, url: u, key: []byte("key")},
		{name: "method", sessionID: "session", url: u, key: []byte("key")},
		{name: "url", sessionID: "session", method: http.MethodGet, key: []byte("key")},
		{name: "key", sessionID: "session", method: http.MethodGet, url: u},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := nativeRequestMAC(tt.sessionID, tt.method, tt.url, 1, tt.key); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestNativeRequestMACMatchesPublicAnalyzerVectors(t *testing.T) {
	tests := []struct {
		want      string
		sessionID string
		requestID uint64
		method    string
		rawURL    string
		key       string
	}{
		{
			want:      "v1|6|oBnE8JLpG2Othzgy",
			sessionID: "RDPMIFQWUJBWZFDBKURHNRFVRA",
			requestID: 6,
			method:    http.MethodGet,
			rawURL:    "https://my.b5local.com:3000/api/v1/invites",
			key:       "ETmGs4U7ReMolW1J64ZAmmksXbQFFbeyRPW6zPWj3VM",
		},
		{
			want:      "v1|7|E2w1PDPlDRKaVEQs",
			sessionID: "RDPMIFQWUJBWZFDBKURHNRFVRA",
			requestID: 7,
			method:    http.MethodGet,
			rawURL:    "https://my.b5local.com:3000/api/v2/users?limit=25&states=P&types=G,R",
			key:       "ETmGs4U7ReMolW1J64ZAmmksXbQFFbeyRPW6zPWj3VM",
		},
		{
			want:      "v1|7|JDqt1exoqPCjZiAJ",
			sessionID: "QVLABIG34RB3TMH7ZJEW47CCKE",
			requestID: 7,
			method:    http.MethodGet,
			rawURL:    "https://my.b5local.com:3000/api/v1/vaults?permission=read&attrs=accessor-previews%2Ccombined-access",
			key:       "-K_oZ-mtamTiLJODQn5cVhXQX-nFmPI2kosmWmOWfZg",
		},
		{
			want:      "v1|3907223784|Htb-Sn_9k4u59wOz",
			sessionID: "VADBXWG7FVC6FIOKOJ4DBGE4SY",
			requestID: 3907223784,
			method:    http.MethodDelete,
			rawURL:    "https://awesome.b5dev.com/api/v1/vault/p3nfd4jax622nqjos7licewuyn",
			key:       "xvoJlJo7KkJGQ55-mjd7tOBE6YvRYnGBNpPoo3_F2M0",
		},
		{
			want:      "v1|781158249|kkvpSd6stufwwlsZ",
			sessionID: "2UG2ZGCDLFAWRHPETAV325EL5U",
			requestID: 781158249,
			method:    http.MethodGet,
			rawURL:    "https://awesome.b5dev.com/api/v1/auditevents/0/older?object_types=gva,invite",
			key:       "WDs9nvg0DYYmQmucwPZ25FV6uUSaYsJUgse7apbs6rk",
		},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			u, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatal(err)
			}
			key, err := base64.RawURLEncoding.DecodeString(tt.key)
			if err != nil {
				t.Fatal(err)
			}
			got, err := nativeRequestMAC(tt.sessionID, tt.method, u, tt.requestID, key)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNativeSessionPayloadMatchesPublicAnalyzerVectors(t *testing.T) {
	tests := []struct {
		name       string
		keyID      string
		sessionKey string
		iv         string
		plaintext  string
		data       string
	}{
		{
			name:       "response",
			keyID:      "YKQRP2M3HZFPZDNXTHQBYFPB5M",
			sessionKey: "6fsZq-Md2jvAM7Bk8qLv0z59y68np5IxLK4RLgI_zog",
			iv:         "tYENu1VjK9bH7Ppn",
			plaintext:  `{"users":[],"totalCount":0}`,
			data:       "ajyndPzqt8mnc2R4x_ZGJSmRY6qqbOKKiEljvvNce1xtHNmc_jdbm5oBbQ",
		},
		{
			name:       "auth request",
			keyID:      "HJM32R3ZHFD6HCXYIEEXSM7EBA",
			sessionKey: "wA7-vBGaq2-CJKvpXm_nmo4Xab0wScgibk_GCjhZfNE",
			iv:         "7CLCnKLlFzakf_K4",
			plaintext:  `{"sessionID":"HJM32R3ZHFD6HCXYIEEXSM7EBA","clientVerifyHash":"fNLywld9ZIMgv1tEyO2DRTtqZ8shnvBEvjm_kEQDjLM","client":"1Password for Web/938","device":{"uuid":"x6w4d6q5sletp2udhklafgu3zy","clientName":"1Password for Web","clientVersion":"938","name":"Firefox","model":"84.0","osName":"MacOSX","osVersion":"10.16","userAgent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.16; rv:84.0) Gecko/20100101 Firefox/84.0"}}`,
			data:       "VvCwMKlCsazav1NNKH2n7x1GSVLe5WEH4ydL4Mpv3LpSe6sd3XR5KWK2OFwgCQ9RkU95gl5g_pLLkfgv9xKZvX7u9c2SrIo1l_owHd2t04ga31z-XfwioCtX2U_zG4GQd0nOa7ds-uOqjNHrP8hA5Wof21g5L6mHAClRzT0kfCX949LDNNDGqbRqZUj0g4R0s6tJ-RQsA7A2BxCKxVvxemyDAE1tuM6gdSuawbUrRmtXbDaItG-kG7Xmz6o4YsF2Y1xAw3I1BiFy9J9wkTZ5S_ORFZKQ2A8JzTxuyR1ou3WvxW8IpVZDKLgpvrjfYl2RSWwKqfASnTaeBShPn5xCMtPPZydm_j_BQ5isxxAqBp9gWSwV2QAowtAm2jQXQ2K27vCeI1N4q6mpMQ2s7t5kdW_gen7be7HcfPH_i921et1aM2uVleCmd-zYUhrahOS4anxYcKsJTiGll_x0yEBlfVwRrN7M5Sr6-taWuVb8OvvbzPi2ShssJNWEf-FsSq6WMNdGJgc2cE2AFcZJIc8GFwLyoS_z203nqO5zVlFbnD_4_rph22tbids",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionKey, err := base64.RawURLEncoding.DecodeString(tt.sessionKey)
			if err != nil {
				t.Fatal(err)
			}
			iv, err := base64.RawURLEncoding.DecodeString(tt.iv)
			if err != nil {
				t.Fatal(err)
			}

			message, err := nativeSealSessionPayload(tt.keyID, sessionKey, iv, []byte(tt.plaintext))
			if err != nil {
				t.Fatal(err)
			}
			if message.Encryption != "A256GCM" || message.ContentType != "b5+jwk+json" {
				t.Fatalf("unexpected envelope: %+v", message)
			}
			if got, want := message.IV, tt.iv; got != want {
				t.Fatalf("got iv %q, want %q", got, want)
			}
			if got, want := message.Data, tt.data; got != want {
				t.Fatalf("got data %q, want %q", got, want)
			}

			message.Data += strings.Repeat("=", (4-len(message.Data)%4)%4)
			plaintext, err := nativeOpenSessionPayload(sessionKey, message)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := string(plaintext), tt.plaintext; got != want {
				t.Fatalf("got plaintext %q, want %q", got, want)
			}
		})
	}
}

func TestDoNativeJSONEncryptsAndDecryptsWithSession(t *testing.T) {
	sessionKey := []byte("12345678901234567890123456789012")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var encrypted nativeEncryptedMessage
		if err := json.NewDecoder(r.Body).Decode(&encrypted); err != nil {
			t.Fatal(err)
		}
		plaintext, err := nativeOpenSessionPayload(sessionKey, encrypted)
		if err != nil {
			t.Fatal(err)
		}
		var request map[string]string
		if err := json.Unmarshal(plaintext, &request); err != nil {
			t.Fatal(err)
		}
		if got, want := request["name"], "vault"; got != want {
			t.Fatalf("got request name %q, want %q", got, want)
		}

		response, err := nativeSealSessionPayload("session-id", sessionKey, []byte("123456789012"), []byte(`{"ok":true}`))
		if err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Fatal(err)
		}
	}))
	defer server.Close()

	base, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &nativeClient{
		baseURL:    base,
		httpClient: server.Client(),
		session:    &nativeSession{ID: "session-id", Key: sessionKey},
	}

	var response struct {
		OK bool `json:"ok"`
	}
	if err := client.doNativeJSON(context.Background(), http.MethodPost, "/api", map[string]string{"name": "vault"}, &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK {
		t.Fatal("expected ok response")
	}
}

func TestDoNativeJSON(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.URL.Path, "/api"; got != want {
			t.Fatalf("got path %q, want %q", got, want)
		}
		if got, want := r.Header.Get("Content-Type"), "application/json"; got != want {
			t.Fatalf("got Content-Type %q, want %q", got, want)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	base, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &nativeClient{baseURL: base, httpClient: server.Client()}

	var response struct {
		OK bool `json:"ok"`
	}
	if err := client.doNativeJSON(context.Background(), http.MethodPost, "/api", map[string]string{"name": "vault"}, &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK {
		t.Fatal("expected ok response")
	}
}

func TestDoNativeJSONRejectsNonSuccessStatus(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "do not leak response body", http.StatusNotFound)
	}))
	defer server.Close()

	base, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &nativeClient{baseURL: base, httpClient: server.Client()}

	err = client.doNativeJSON(context.Background(), http.MethodGet, "/api", nil, nil)
	if err == nil {
		t.Fatal("expected status error")
	}
	if got := err.Error(); got != `{"name":"NotFound","message":"resource not found"}` || strings.Contains(got, "do not leak") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNativeHTTPStatusError(t *testing.T) {
	tests := map[int]string{
		http.StatusBadRequest:          `{"name":"InvalidUserInput","message":"bad request sent to the server"}`,
		http.StatusUnauthorized:        `{"name":"Unauthenticated","message":"you are not authenticated"}`,
		http.StatusForbidden:           `{"name":"PermissionDenied","message":"you don't have the right permissions to access this resource"}`,
		http.StatusConflict:            `{"name":"Conflict","message":"a conflict occurred on the server"}`,
		http.StatusTooManyRequests:     `{"name":"RateLimitExceeded","message":"rate limit exceeded"}`,
		http.StatusInternalServerError: `{"name":"ServerError","message":"native API request failed with status 500"}`,
	}
	for status, want := range tests {
		if got := nativeHTTPStatusError(status).Error(); got != want {
			t.Fatalf("status %d got %q, want %q", status, got, want)
		}
	}
}

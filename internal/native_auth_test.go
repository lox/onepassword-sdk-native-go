package internal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestParseServiceAccountToken(t *testing.T) {
	token := testServiceAccountToken(t)

	creds, err := parseServiceAccountToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if creds.SignInAddress != "example.1password.com:4000" {
		t.Fatalf("unexpected sign-in address: %q", creds.SignInAddress)
	}
	if creds.DeviceUUID != testDeviceUUID {
		t.Fatalf("unexpected device uuid: %q", creds.DeviceUUID)
	}
	if creds.UserAuth.empty() {
		t.Fatal("expected userAuth")
	}
}

func TestParseServiceAccountTokenFromDocs(t *testing.T) {
	token := encodeServiceAccountCredentials(t, serviceAccountCredentials{
		Email:     "ejwe64qmlxhri@1passwordserviceaccounts.lcl",
		SecretKey: "A3-C4ZJMN-PQTZTL-HGL84-G64M7-KVZRN-4ZVP6",
		SRPX:      "870d67a9e626625d9e368507804c9c32e661c57e7e558778291bf29d5a279ae1",
		MUK: serviceAccountJWK{
			Alg:    "A256GCM",
			Ext:    true,
			K:      "M8VPfIc8VEfThcMXLaKCKF8sMh5JMZsPAtu92fQNb-o",
			KeyOps: []string{"encrypt", "decrypt"},
			Kty:    "oct",
			KID:    "mp",
		},
		SignInAddress: "gotham.b5local.com:4000",
		UserAuth: serviceAccountUserAuth{
			Method:     "SRPg-4096",
			Alg:        "PBES2g-HS256",
			Iterations: 100000,
			Salt:       "FMRUPiyrN4Xf_8Hoh6YRXQ",
		},
		ThrottleSecret: serviceAccountThrottleSecret{
			Seed: "ddc20da89d71ff640f36bb6c446c64d56a2123eb4e7bd9c89ce303075eea5780",
			UUID: "TP4Z5ZB7IJABDPGIVSUZLY4T5A",
		},
		DeviceUUID: "ay5shynibdyqisjz3j63b7uygy",
	})

	creds, err := parseServiceAccountToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := creds.SignInAddress, "gotham.b5local.com:4000"; got != want {
		t.Fatalf("got signInAddress %q, want %q", got, want)
	}
	if got, want := creds.UserAuth.Method, "SRPg-4096"; got != want {
		t.Fatalf("got auth method %q, want %q", got, want)
	}
	if got, want := creds.MUK.KID, "mp"; got != want {
		t.Fatalf("got muk kid %q, want %q", got, want)
	}
}

func TestParseServiceAccountTokenRejectsMalformedToken(t *testing.T) {
	_, err := parseServiceAccountToken("dummy")
	if err == nil {
		t.Fatal("expected malformed token error")
	}
	if !strings.Contains(err.Error(), "must start with ops_") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseServiceAccountTokenRejectsMissingFields(t *testing.T) {
	payload, err := json.Marshal(map[string]string{"signInAddress": "https://example.1password.com"})
	if err != nil {
		t.Fatal(err)
	}

	_, err = parseServiceAccountToken("ops_" + base64.RawURLEncoding.EncodeToString(payload))
	if err == nil {
		t.Fatal("expected missing fields error")
	}
	if !strings.Contains(err.Error(), "service account token is missing") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseServiceAccountTokenRejectsMissingUserAuth(t *testing.T) {
	payload, err := json.Marshal(serviceAccountCredentials{
		SignInAddress: "example.1password.com:4000",
		Email:         "service@example.com",
		SecretKey:     testSecretKey,
		SRPX:          "srpx",
		MUK: serviceAccountJWK{
			Alg: "A256GCM",
			K:   "key",
			Kty: "oct",
			KID: "mp",
		},
		DeviceUUID:     testDeviceUUID,
		ThrottleSecret: serviceAccountThrottleSecret{Seed: "seed", UUID: testThrottleUUID},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = parseServiceAccountToken("ops_" + base64.RawURLEncoding.EncodeToString(payload))
	if err == nil {
		t.Fatal("expected null userAuth error")
	}
	if !strings.Contains(err.Error(), "userAuth") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseServiceAccountTokenRejectsUnsupportedUserAuth(t *testing.T) {
	creds := testServiceAccountCredentials()
	creds.UserAuth.Alg = "unsupported"
	token := encodeServiceAccountCredentials(t, creds)

	_, err := parseServiceAccountToken(token)
	if err == nil {
		t.Fatal("expected unsupported userAuth error")
	}
	if !strings.Contains(err.Error(), `unsupported userAuth alg`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseServiceAccountTokenRejectsBadUserAuthSalt(t *testing.T) {
	creds := testServiceAccountCredentials()
	creds.UserAuth.Salt = "%"
	token := encodeServiceAccountCredentials(t, creds)

	_, err := parseServiceAccountToken(token)
	if err == nil {
		t.Fatal("expected bad salt error")
	}
	if !strings.Contains(err.Error(), `decode userAuth salt`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseServiceAccountTokenRejectsBadSRPX(t *testing.T) {
	creds := testServiceAccountCredentials()
	creds.SRPX = "srpx"
	token := encodeServiceAccountCredentials(t, creds)

	_, err := parseServiceAccountToken(token)
	if err == nil {
		t.Fatal("expected bad srpX error")
	}
	if !strings.Contains(err.Error(), "decode srpX") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseServiceAccountTokenRejectsBadDeviceIDs(t *testing.T) {
	tests := []struct {
		name string
		edit func(*serviceAccountCredentials)
		want string
	}{
		{
			name: "device uuid",
			edit: func(creds *serviceAccountCredentials) { creds.DeviceUUID = "device" },
			want: `parameter "deviceUuid" must be a 26-character 1Password ID`,
		},
		{
			name: "throttle uuid",
			edit: func(creds *serviceAccountCredentials) { creds.ThrottleSecret.UUID = "uuid" },
			want: `parameter "throttleSecret.uuid" must be a 26-character 1Password ID`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds := testServiceAccountCredentials()
			tt.edit(&creds)
			_, err := parseServiceAccountToken(encodeServiceAccountCredentials(t, creds))
			if err == nil {
				t.Fatal("expected device id error")
			}
			if got := err.Error(); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseServiceAccountTokenRejectsBadSecretKey(t *testing.T) {
	tests := []struct {
		name      string
		secretKey string
		want      string
	}{
		{
			name:      "shape",
			secretKey: "secret-key",
			want:      "secretKey must have format A3-XXXXXX-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
		},
		{
			name:      "version",
			secretKey: "A4-C4ZJMN-PQTZTL-HGL84-G64M7-KVZRN-4ZVP6",
			want:      `unsupported secretKey version "A4"`,
		},
		{
			name:      "case",
			secretKey: "A3-c4ZJMN-PQTZTL-HGL84-G64M7-KVZRN-4ZVP6",
			want:      "secretKey must contain only uppercase letters, digits, and hyphens",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds := testServiceAccountCredentials()
			creds.SecretKey = tt.secretKey
			_, err := parseServiceAccountToken(encodeServiceAccountCredentials(t, creds))
			if err == nil {
				t.Fatal("expected secretKey error")
			}
			if got := err.Error(); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestServiceAccountCredentialsAuthStartRequest(t *testing.T) {
	request, err := testServiceAccountCredentials().authStartRequest()
	if err != nil {
		t.Fatal(err)
	}

	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"email":"service@example.com","skFormat":"A3","skid":"C4ZJMN","deviceUuid":"abcdefghijklmnopqrstuvwx12"}`
	if got := string(body); got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestNativeClientStartAuth(t *testing.T) {
	creds := testServiceAccountCredentials()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Method, http.MethodPost; got != want {
			t.Fatalf("got method %q, want %q", got, want)
		}
		if got, want := r.URL.String(), "/api/v3/auth/start"; got != want {
			t.Fatalf("got path %q, want %q", got, want)
		}
		if r.Header.Get("X-AgileBits-Session-ID") != "" || r.Header.Get("X-AgileBits-MAC") != "" {
			t.Fatalf("auth start must not send session headers")
		}
		var request nativeAuthStartRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.Email != creds.Email || request.SKFormat != "A3" || request.SKID != "C4ZJMN" || request.DeviceUUID != creds.DeviceUUID {
			t.Fatalf("unexpected auth start request: %+v", request)
		}
		if err := json.NewEncoder(w).Encode(nativeAuthStartResponse{
			Status:           "ok",
			SessionID:        "abcdefghijklmnopqrstuvwx56",
			AccountKeyFormat: "A3",
			AccountKeyUUID:   "C4ZJMN",
			UserAuth:         creds.UserAuth,
		}); err != nil {
			t.Fatal(err)
		}
	}))
	defer server.Close()

	client := nativeAuthTestClient(t, server, creds)
	response, err := client.startAuth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if response.SessionID != "abcdefghijklmnopqrstuvwx56" {
		t.Fatalf("got sessionID %q", response.SessionID)
	}
}

func TestNativeClientStartAuthRejectsMismatchedAccountKey(t *testing.T) {
	creds := testServiceAccountCredentials()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(nativeAuthStartResponse{
			Status:           "ok",
			SessionID:        "abcdefghijklmnopqrstuvwx56",
			AccountKeyFormat: "A3",
			AccountKeyUUID:   "WRONG1",
			UserAuth:         creds.UserAuth,
		}); err != nil {
			t.Fatal(err)
		}
	}))
	defer server.Close()

	_, err := nativeAuthTestClient(t, server, creds).startAuth(context.Background())
	if err == nil {
		t.Fatal("expected account key mismatch")
	}
	if got, want := err.Error(), "auth start accountKeyUuid mismatch"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNativeAuthStartResponseAuthRequest(t *testing.T) {
	request, err := nativeAuthStartResponse{SessionID: "abcdefghijklmnopqrstuvwx56"}.authRequest("deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(body), `{"userA":"deadbeef"}`; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}

	if _, err := (nativeAuthStartResponse{}).authRequest("deadbeef"); err == nil {
		t.Fatal("expected missing sessionID error")
	}
	if _, err := (nativeAuthStartResponse{SessionID: "abcdefghijklmnopqrstuvwx56"}).authRequest(""); err == nil {
		t.Fatal("expected missing userA error")
	}
}

func TestNativeAuthStartResponseSRPAuthRequest(t *testing.T) {
	request, err := nativeAuthStartResponse{SessionID: "H27JRK5M4NBJXOBCOETCVXJHFA"}.srpAuthRequest(nativeSRPMustHex("f1ecc95bb29e8a360e9b257d5688c83d503506a6a6eba683f1e06"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := request.SessionID, "H27JRK5M4NBJXOBCOETCVXJHFA"; got != want {
		t.Fatalf("got sessionID %q, want %q", got, want)
	}
	if got, want := request.UserA, nativeSRPTestUserA; got != want {
		t.Fatalf("got userA %s, want %s", got, want)
	}

	if _, err := (nativeAuthStartResponse{SessionID: "session"}).srpAuthRequest(nativeSRPMustHex("1")); err == nil {
		t.Fatal("expected bad session id error")
	}
}

func TestNativeAuthStartResponseGeneratedSRPAuthRequest(t *testing.T) {
	response := nativeAuthStartResponse{SessionID: "H27JRK5M4NBJXOBCOETCVXJHFA"}
	request, ephemeralPrivate, err := response.generatedSRPAuthRequest()
	if err != nil {
		t.Fatal(err)
	}
	if request.SessionID != response.SessionID {
		t.Fatalf("got sessionID %q, want %q", request.SessionID, response.SessionID)
	}
	wantUserA, err := nativeSRPClientPublicHex(ephemeralPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if request.UserA != wantUserA {
		t.Fatalf("got userA %q, want %q", request.UserA, wantUserA)
	}

	if _, _, err := (nativeAuthStartResponse{SessionID: "session"}).generatedSRPAuthRequest(); err == nil {
		t.Fatal("expected bad session id error")
	}
}

func TestNativeClientAuthExchangeUsesAuthRoute(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Method, http.MethodPost; got != want {
			t.Fatalf("got method %q, want %q", got, want)
		}
		if got, want := r.URL.String(), "/api/v2/auth"; got != want {
			t.Fatalf("got path %q, want %q", got, want)
		}
		var body struct {
			UserA string `json:"userA"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.UserA != "deadbeef" {
			t.Fatalf("unexpected auth request: %+v", body)
		}
		if err := json.NewEncoder(w).Encode(nativeAuthResponse{
			SessionID:        "abcdefghijklmnopqrstuvwx56",
			UserB:            nativeSRPServerStyleHex(big.NewInt(5)),
			ServerVerifyHash: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		}); err != nil {
			t.Fatal(err)
		}
	}))
	defer server.Close()

	client := nativeHTTPTestClient(t, server, nil)
	client.session = nil
	response, err := client.authExchange(context.Background(), nativeAuthRequest{
		SessionID: "abcdefghijklmnopqrstuvwx56",
		UserA:     "deadbeef",
	})
	if err != nil {
		t.Fatal(err)
	}
	serverB, err := response.serverPublic()
	if err != nil {
		t.Fatal(err)
	}
	if serverB.Cmp(big.NewInt(5)) != 0 {
		t.Fatalf("got userB %s, want 5", serverB.Text(16))
	}
	proof, err := response.serverProof()
	if err != nil {
		t.Fatal(err)
	}
	if len(proof) != 32 {
		t.Fatalf("got proof length %d, want 32", len(proof))
	}
}

func TestNativeClientVerifyAuthUsesConfirmKeyRoute(t *testing.T) {
	sessionKey := []byte("12345678901234567890123456789012")
	clientProof := bytes.Repeat([]byte{2}, 32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Method, http.MethodPost; got != want {
			t.Fatalf("got method %q, want %q", got, want)
		}
		if got, want := r.URL.String(), "/api/v2/auth/confirm-key"; got != want {
			t.Fatalf("got path %q, want %q", got, want)
		}
		var body nativeAuthVerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if got, want := body.ClientVerifyHash, base64.RawURLEncoding.EncodeToString(clientProof); got != want {
			t.Fatalf("got clientVerifyHash %q, want %q", got, want)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := nativeHTTPTestClient(t, server, nil)
	client.session = nil
	client.creds = testServiceAccountCredentials()
	client.config = NewDefaultConfig()
	if err := client.verifyAuth(context.Background(), "abcdefghijklmnopqrstuvwx56", nativeSRPCompletion{
		SessionKey:  sessionKey,
		ClientProof: clientProof,
	}); err != nil {
		t.Fatal(err)
	}
	if client.session == nil || client.session.ID != "abcdefghijklmnopqrstuvwx56" {
		t.Fatalf("session was not established: %+v", client.session)
	}
}

func TestNativeClientEnsureSessionRunsSRPAuthFlow(t *testing.T) {
	creds := testServiceAccountCredentials()
	keys, err := creds.keyMaterial()
	if err != nil {
		t.Fatal(err)
	}

	sessionID := "abcdefghijklmnopqrstuvwx56"
	var sessionKey []byte
	var serverProof []byte
	var clientA *big.Int
	serverPrivate := nativeSRPMustHex("123456789abcdef")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.String() {
		case "/api/v3/auth/start":
			var request nativeAuthStartRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.Email != creds.Email || request.SKFormat != "A3" || request.SKID != "C4ZJMN" {
				t.Fatalf("unexpected auth start request: %+v", request)
			}
			if err := json.NewEncoder(w).Encode(nativeAuthStartResponse{
				Status:           "ok",
				SessionID:        sessionID,
				AccountKeyFormat: "A3",
				AccountKeyUUID:   "C4ZJMN",
				UserAuth:         creds.UserAuth,
			}); err != nil {
				t.Fatal(err)
			}
		case "/api/v2/auth":
			var request nativeAuthRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			var ok bool
			clientA, ok = new(big.Int).SetString(request.UserA, 16)
			if !ok {
				t.Fatalf("bad userA %q", request.UserA)
			}
			serverB, key, proof, err := nativeTestSRPServerResponse(sessionID, creds.Email, keys, clientA, serverPrivate)
			if err != nil {
				t.Fatal(err)
			}
			sessionKey = key
			serverProof = proof
			if err := json.NewEncoder(w).Encode(nativeAuthResponse{
				UserB:            nativeSRPServerStyleHex(serverB),
				ServerVerifyHash: base64.RawURLEncoding.EncodeToString(proof),
			}); err != nil {
				t.Fatal(err)
			}
		case "/api/v2/auth/confirm-key":
			var request nativeAuthVerifyRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			expectedProof, err := nativeSRPClientProof(clientA, serverProof, sessionKey)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := request.ClientVerifyHash, base64.RawURLEncoding.EncodeToString(expectedProof); got != want {
				t.Fatalf("got clientVerifyHash %q, want %q", got, want)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected path %q", r.URL.String())
		}
	}))
	defer server.Close()

	client := nativeHTTPTestClient(t, server, nil)
	client.session = nil
	client.creds = creds
	client.keys = keys
	client.config = NewDefaultConfig()
	if err := client.ensureSession(context.Background()); err != nil {
		t.Fatal(err)
	}
	if client.session == nil || client.session.ID != sessionID || !bytes.Equal(client.session.Key, sessionKey) {
		t.Fatalf("unexpected session: %+v", client.session)
	}
}

func nativeTestSRPServerResponse(sessionID, email string, keys serviceAccountKeyMaterial, clientA, serverPrivate *big.Int) (*big.Int, []byte, []byte, error) {
	x := new(big.Int).SetBytes(keys.SRPX)
	k, err := nativeSRPMultiplier(sessionID)
	if err != nil {
		return nil, nil, nil, err
	}
	verifier := new(big.Int).Exp(nativeSRP4096G, x, nativeSRP4096N)
	serverB := new(big.Int).Exp(nativeSRP4096G, serverPrivate, nativeSRP4096N)
	serverB.Add(serverB, new(big.Int).Mul(k, verifier))
	serverB.Mod(serverB, nativeSRP4096N)
	u, err := nativeSRPClientU(clientA, serverB)
	if err != nil {
		return nil, nil, nil, err
	}
	premasterBase := new(big.Int).Exp(verifier, u, nativeSRP4096N)
	premasterBase.Mul(premasterBase, clientA)
	premasterBase.Mod(premasterBase, nativeSRP4096N)
	premaster := new(big.Int).Exp(premasterBase, serverPrivate, nativeSRP4096N)
	sum := sha256.Sum256([]byte(premaster.Text(16)))
	sessionKey := sum[:]
	proof, err := nativeSRPServerProof(keys.UserAuthSalt, email, clientA, serverB, sessionKey)
	if err != nil {
		return nil, nil, nil, err
	}
	return serverB, sessionKey, proof, nil
}

func TestNativeSRPMultiplier(t *testing.T) {
	multiplier, err := nativeSRPMultiplier("H27JRK5M4NBJXOBCOETCVXJHFA")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(multiplier.Bytes()), "4832374a524b354d344e424a584f42434f45544356584a484641"; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}

	if _, err := nativeSRPMultiplier("session"); err == nil {
		t.Fatal("expected bad session id error")
	}
}

func TestNativeAuthStartResponseCompleteSRP(t *testing.T) {
	sessionID := "H27JRK5M4NBJXOBCOETCVXJHFA"
	ephemeralPrivate := nativeSRPMustHex("f1ecc95bb29e8a360e9b257d5688c83d503506a6a6eba683f1e06")
	serverB := nativeSRPMustHex("780a5495cbf731d2463fd01d28822e7d9ccf697c4239d5151f85666aa06b3767e0301b54cfad3bd2b526d4d8a1d96492e59c8d8ecddca96b7e288f186155ffa57b50df6bc2103b6004400b797334a22d9dd234b40142a5ab714ea6070d2ed55096049f50efba99862b72f7e7aee51ed71ba6663fff570cc713d456316f3535630e87a245f09b0791c6e687baa65bf2dfb5c17e50c250256cdad4c9851a2484e88326888060ae9578b5a60e0c85143b25f4fb4fca794e266a4359642da085672d6a3b881649a387875685aeb1ae3d809bf7818dcad596c6e29d566ae87c0ad645a0fcc2eb4f066c097670adf48cf0954918fda4dc30588261321d592f890eed87a950d387b48cf6b4a49f9d497323f683091ae6a4efe675d6bfc4393c0c3d54c9adad65b8dd3a7b7e85cd5d31e97bebc8f23b370348dab53903ec5085cbf65de5e5491f417e5bf9953f081e788f36c26cbe00664a1256c4befb00765ea7e432af189521442c186f14442b1957e444426f740f363ebda943da2bb3b18a13e2f41be9cc3ca0a1b111f6983f9b8d0ee0f4b573c6042fbc0ca029821ebe517ed0755a94f42d32b0abef9240af0f37b5fe0e90c4ca83acf91d28a7f3acff5657bf69fdb7747e380b23fd437f637da2f7ebcf8733a69a75715fe3894e1799906b48e3ae818332cf5f9533e7af5a1f065f907c8f31fe778fa2da853e69926fc551d6b3ae")
	clientA, err := nativeSRPClientPublicA(ephemeralPrivate)
	if err != nil {
		t.Fatal(err)
	}
	u, err := nativeSRPClientU(clientA, serverB)
	if err != nil {
		t.Fatal(err)
	}
	sessionKey, err := nativeSRPClientRawKey(
		nativeSRPMustHex("740299d2306764ad9e87f37cd54179e388fd45c85fea3b030eb425d7adcb2773"),
		ephemeralPrivate,
		serverB,
		u,
		nativeSRPMustHex("4832374a524b354d344e424a584f42434f45544356584a484641"),
	)
	if err != nil {
		t.Fatal(err)
	}
	salt := []byte("salt")
	email := "service@example.com"
	serverProof, err := nativeSRPServerProof(salt, email, clientA, serverB, sessionKey)
	if err != nil {
		t.Fatal(err)
	}

	got, err := (nativeAuthStartResponse{SessionID: sessionID}).completeSRP(serviceAccountKeyMaterial{
		SRPX:         nativeSRPMustHex("740299d2306764ad9e87f37cd54179e388fd45c85fea3b030eb425d7adcb2773").Bytes(),
		UserAuthSalt: salt,
	}, email, ephemeralPrivate, serverB, serverProof)
	if err != nil {
		t.Fatal(err)
	}
	if !equalBytes(got.SessionKey, sessionKey) {
		t.Fatalf("got session key %x, want %x", got.SessionKey, sessionKey)
	}
	if len(got.ClientProof) != 32 {
		t.Fatalf("got client proof length %d, want 32", len(got.ClientProof))
	}

	if _, err := (nativeAuthStartResponse{SessionID: sessionID}).completeSRP(serviceAccountKeyMaterial{
		SRPX:         nativeSRPMustHex("740299d2306764ad9e87f37cd54179e388fd45c85fea3b030eb425d7adcb2773").Bytes(),
		UserAuthSalt: salt,
	}, email, ephemeralPrivate, serverB, []byte("wrong")); err == nil {
		t.Fatal("expected server proof mismatch")
	}
}

func TestServiceAccountCredentialsKeyMaterial(t *testing.T) {
	keys, err := testServiceAccountCredentials().keyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.MUK) != 32 {
		t.Fatalf("got muk length %d, want 32", len(keys.MUK))
	}
	if len(keys.SRPX) != 32 {
		t.Fatalf("got srpX length %d, want 32", len(keys.SRPX))
	}
	if len(keys.UserAuthSalt) != len("salt") {
		t.Fatalf("got salt length %d, want %d", len(keys.UserAuthSalt), len("salt"))
	}
	if len(keys.ThrottleSecret) != 32 {
		t.Fatalf("got throttle secret length %d, want 32", len(keys.ThrottleSecret))
	}
}

func TestServiceAccountCredentialsKeyMaterialRejectsBadMUK(t *testing.T) {
	creds := testServiceAccountCredentials()
	creds.MUK.K = "%"
	if _, err := creds.keyMaterial(); err == nil {
		t.Fatal("expected bad muk key error")
	}
}

func TestServiceAccountCredentialsKeyMaterialRejectsUnsupportedMUKMetadata(t *testing.T) {
	tests := []struct {
		name string
		edit func(*serviceAccountCredentials)
		want string
	}{
		{
			name: "kid",
			edit: func(creds *serviceAccountCredentials) { creds.MUK.KID = "other" },
			want: `unsupported muk kid "other"`,
		},
		{
			name: "key ops",
			edit: func(creds *serviceAccountCredentials) { creds.MUK.KeyOps = []string{"encrypt"} },
			want: "muk key_ops must include encrypt and decrypt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds := testServiceAccountCredentials()
			tt.edit(&creds)
			_, err := creds.keyMaterial()
			if err == nil {
				t.Fatal("expected muk metadata error")
			}
			if got := err.Error(); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestServiceAccountCredentialsKeyMaterialRejectsBadThrottleSecret(t *testing.T) {
	creds := testServiceAccountCredentials()
	creds.ThrottleSecret.Seed = "%"
	if _, err := creds.keyMaterial(); err == nil {
		t.Fatal("expected bad throttle secret error")
	}
}

func nativeAuthTestClient(t *testing.T, server *httptest.Server, creds serviceAccountCredentials) *nativeClient {
	t.Helper()
	baseURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &nativeClient{
		creds:      creds,
		baseURL:    baseURL,
		httpClient: server.Client(),
	}
}

func testServiceAccountToken(t *testing.T) string {
	t.Helper()
	return encodeServiceAccountCredentials(t, testServiceAccountCredentials())
}

func testServiceAccountCredentials() serviceAccountCredentials {
	return serviceAccountCredentials{
		SignInAddress: "example.1password.com:4000",
		Email:         "service@example.com",
		SecretKey:     testSecretKey,
		SRPX:          strings.Repeat("1", 64),
		MUK: serviceAccountJWK{
			Alg:    "A256GCM",
			Ext:    true,
			K:      testEncoded32ByteKey(),
			KeyOps: []string{"encrypt", "decrypt"},
			Kty:    "oct",
			KID:    "mp",
		},
		UserAuth: serviceAccountUserAuth{
			Alg:        "PBES2g-HS256",
			Iterations: 100000,
			Method:     "SRPg-4096",
			Salt:       base64.RawURLEncoding.EncodeToString([]byte("salt")),
		},
		DeviceUUID:     testDeviceUUID,
		ThrottleSecret: serviceAccountThrottleSecret{Seed: strings.Repeat("a", 64), UUID: testThrottleUUID},
	}
}

const (
	testSecretKey    = "A3-C4ZJMN-PQTZTL-HGL84-G64M7-KVZRN-4ZVP6"
	testDeviceUUID   = "abcdefghijklmnopqrstuvwx12"
	testThrottleUUID = "abcdefghijklmnopqrstuvwx34"
)

func testEncoded32ByteKey() string {
	return base64.RawURLEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
}

func encodeServiceAccountCredentials(t *testing.T, creds serviceAccountCredentials) string {
	t.Helper()
	payload, err := json.Marshal(creds)
	if err != nil {
		t.Fatal(err)
	}
	return "ops_" + base64.RawURLEncoding.EncodeToString(payload)
}

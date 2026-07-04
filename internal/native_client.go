package internal

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// nativeHTTPTimeout bounds every native API request; without it a blackholed
// connection blocks the per-client mutex and deadlocks all other calls.
const nativeHTTPTimeout = 60 * time.Second

type nativeClient struct {
	mu         sync.Mutex
	config     ClientConfig
	creds      serviceAccountCredentials
	keys       serviceAccountKeyMaterial
	baseURL    *url.URL
	httpClient *http.Client
	session    *nativeSession
	// Decrypted key material memoized for the lifetime of the session;
	// cleared by invalidateSession.
	keysetCache   map[string]nativeSymmetricKey
	vaultKeyCache map[string]map[int]nativeSymmetricKey
}

type nativeSession struct {
	ID            string
	Key           []byte
	NextRequestID uint64
}

func newNativeClient(config ClientConfig, creds serviceAccountCredentials) (*nativeClient, error) {
	baseURL, err := nativeAccountBaseURL(creds.SignInAddress)
	if err != nil {
		return nil, err
	}
	keys, err := creds.keyMaterial()
	if err != nil {
		return nil, err
	}
	return &nativeClient{
		config:     config,
		creds:      creds,
		keys:       keys,
		baseURL:    baseURL,
		httpClient: nativeDefaultHTTPClient(),
	}, nil
}

func nativeAccountBaseURL(signInAddress string) (*url.URL, error) {
	address := strings.TrimSpace(signInAddress)
	if address == "" {
		return nil, fmt.Errorf("signInAddress is required")
	}
	if !strings.Contains(address, "://") {
		address = "https://" + address
	}

	u, err := url.Parse(address)
	if err != nil {
		return nil, fmt.Errorf("parse signInAddress: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("signInAddress must use https")
	}
	if u.Host == "" {
		return nil, fmt.Errorf("signInAddress must include a host")
	}
	if !nativeAllowedAccountHost(u.Hostname()) {
		return nil, fmt.Errorf("signInAddress must be a 1Password account host")
	}
	if u.User != nil {
		return nil, fmt.Errorf("signInAddress must not include user info")
	}
	if u.RawQuery != "" {
		return nil, fmt.Errorf("signInAddress must not include query parameters")
	}
	if u.Fragment != "" {
		return nil, fmt.Errorf("signInAddress must not include a fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("signInAddress must not include a path")
	}
	u.User = nil
	u.Path = ""
	return u, nil
}

func nativeAllowedAccountHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return false
	}
	for _, suffix := range []string{
		".1password.com",
		".1password.ca",
		".1password.eu",
		".b5staging.com",
		".b5dev.com",
		".b5dev.ca",
		".b5dev.eu",
		".b5test.com",
		".b5test.ca",
		".b5test.eu",
		".b5rev.com",
		".b5local.com",
	} {
		if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
			return true
		}
	}
	return false
}

func nativeDefaultHTTPClient() *http.Client {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return &http.Client{Timeout: nativeHTTPTimeout}
	}
	cloned := transport.Clone()
	cloned.DisableCompression = true
	return &http.Client{Transport: cloned, Timeout: nativeHTTPTimeout}
}

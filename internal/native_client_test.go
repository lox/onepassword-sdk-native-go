package internal

import (
	"net/http"
	"testing"
)

func TestNativeAccountBaseURL(t *testing.T) {
	u, err := nativeAccountBaseURL("https://example.1password.com/")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := u.String(), "https://example.1password.com"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNativeAccountBaseURLAcceptsBareHost(t *testing.T) {
	u, err := nativeAccountBaseURL("example.1password.com:4000")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := u.String(), "https://example.1password.com:4000"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNativeAccountBaseURLAcceptsDocumentedLocalHostFamily(t *testing.T) {
	u, err := nativeAccountBaseURL("gotham.b5local.com:4000")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := u.String(), "https://gotham.b5local.com:4000"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNativeAccountBaseURLRejectsUnsafeAddresses(t *testing.T) {
	for _, address := range []string{
		"",
		"http://example.1password.com",
		"https://",
		"https://example.com",
		"https://1password.com",
		"https://not1password.com",
		"https://user@example.1password.com",
		"https://example.1password.com/path",
		"https://example.1password.com?token=secret",
		"https://example.1password.com#fragment",
	} {
		t.Run(address, func(t *testing.T) {
			if _, err := nativeAccountBaseURL(address); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestNativeDefaultHTTPClientDisablesCompression(t *testing.T) {
	client := nativeDefaultHTTPClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("got transport %T", client.Transport)
	}
	if !transport.DisableCompression {
		t.Fatal("expected native HTTP compression to be disabled")
	}
}

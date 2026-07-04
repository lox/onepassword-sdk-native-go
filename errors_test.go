package onepassword

import (
	"errors"
	"testing"
)

func TestUnmarshalErrorRateLimitExceeded(t *testing.T) {
	var rateLimited *RateLimitExceededError
	if !errors.As(unmarshalError(`{"name":"RateLimitExceeded","message":"rate limit exceeded"}`), &rateLimited) {
		t.Fatal("expected RateLimitExceededError")
	}
}

func TestUnmarshalErrorPreservesName(t *testing.T) {
	err := unmarshalError(`{"name":"NotFound","message":"resource not found"}`)
	var typed *Error
	if !errors.As(err, &typed) || typed.Name != "NotFound" || typed.Message != "resource not found" {
		t.Fatalf("got %#v", err)
	}
	if err.Error() != "resource not found" {
		t.Fatalf("got %q", err.Error())
	}
}

func TestUnmarshalErrorNeverEmpty(t *testing.T) {
	if got := unmarshalError(`{"name":"Internal"}`).Error(); got == "" {
		t.Fatal("expected non-empty error message")
	}
	if got := unmarshalError("plain text error").Error(); got != "plain text error" {
		t.Fatalf("got %q", got)
	}
}

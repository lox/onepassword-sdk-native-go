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

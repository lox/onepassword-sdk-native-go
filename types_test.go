package onepassword

import (
	"encoding/json"
	"testing"
)

func TestResolveReferenceErrorUnmarshalWithoutMessage(t *testing.T) {
	// The native core emits this variant without a message key; decoding must
	// not fail the whole ResolveAll response.
	var r ResolveReferenceError
	if err := json.Unmarshal([]byte(`{"type":"unableToGenerateTotpCode"}`), &r); err != nil {
		t.Fatal(err)
	}
	if r.Type != ResolveReferenceErrorTypeVariantUnableToGenerateTOTPCode {
		t.Fatalf("got type %q", r.Type)
	}
	if got := r.UnableToGenerateTOTPCode(); got != "" {
		t.Fatalf("got message %q, want empty", got)
	}
}

func TestUnionAccessorsTolerateWrongVariant(t *testing.T) {
	details := NewItemFieldDetailsTypeVariantOTP(&OTPFieldDetails{})
	if details.SSHKey() != nil {
		t.Fatal("expected nil SSHKey for OTP variant")
	}
	if details.Address() != nil {
		t.Fatal("expected nil Address for OTP variant")
	}
	reason := NewItemUpdateFailureReasonTypeVariantItemStatusPermissionError()
	if got := reason.Internal(); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
	if got := reason.ItemValidationError(); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

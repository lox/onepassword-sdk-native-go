package onepassword

import (
	"context"
	"strings"
	"testing"
)

func TestValidateSecretReference(t *testing.T) {
	valid := []string{
		"op://vault/item/field",
		"op://vault/item/section/field",
		"op://vault/item/field?attribute=totp",
		"op://vault%20name/item%20name/field%20name",
	}
	for _, ref := range valid {
		if err := validateSecretReference(ref); err != nil {
			t.Fatalf("expected %q to validate: %v", ref, err)
		}
	}

	invalid := []string{
		"",
		"https://vault/item/field",
		"op://",
		"op://vault",
		"op://vault/item",
		"op://vault/item/section/extra/field",
		"op://vault/item/",
		"op://vault/item/field#fragment",
		"op://vault/item/field?attribute=totp#fragment",
		"op://vault/item/field?unknown=value",
		"op://vault/item/field?attribute=",
		"op://vault/item/field?attribute=totp&attribute=concealed",
		"op://vault%2Fname/item/field",
	}
	for _, ref := range invalid {
		if err := validateSecretReference(ref); err == nil {
			t.Fatalf("expected %q to fail validation", ref)
		}
	}
}

func TestGeneratePinPassword(t *testing.T) {
	result, ok, err := generatePassword(NewPasswordRecipeTypeVariantPin(&PasswordRecipePinInner{Length: 10}))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected native PIN generation")
	}
	if len(result.Password) != 10 {
		t.Fatalf("expected length 10, got %d", len(result.Password))
	}
	if strings.Trim(result.Password, passwordDigits) != "" {
		t.Fatalf("expected only digits, got %q", result.Password)
	}
}

func TestGenerateRandomPassword(t *testing.T) {
	result, ok, err := generatePassword(NewPasswordRecipeTypeVariantRandom(&PasswordRecipeRandomInner{
		IncludeDigits:  true,
		IncludeSymbols: true,
		Length:         24,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected native random generation")
	}
	if len(result.Password) != 24 {
		t.Fatalf("expected length 24, got %d", len(result.Password))
	}
	if !strings.ContainsAny(result.Password, passwordDigits) {
		t.Fatalf("expected a digit in %q", result.Password)
	}
	if !strings.ContainsAny(result.Password, passwordSymbols) {
		t.Fatalf("expected a symbol in %q", result.Password)
	}
}

func TestGenerateRandomPasswordMinimumRequiredLength(t *testing.T) {
	result, ok, err := generatePassword(NewPasswordRecipeTypeVariantRandom(&PasswordRecipeRandomInner{
		IncludeDigits:  true,
		IncludeSymbols: true,
		Length:         2,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected native random generation")
	}
	if len(result.Password) != 2 {
		t.Fatalf("expected length 2, got %d", len(result.Password))
	}
	if !strings.ContainsAny(result.Password, passwordDigits) {
		t.Fatalf("expected a digit in %q", result.Password)
	}
	if !strings.ContainsAny(result.Password, passwordSymbols) {
		t.Fatalf("expected a symbol in %q", result.Password)
	}
}

func TestGeneratePasswordMemorableUnsupported(t *testing.T) {
	_, ok, err := generatePassword(NewPasswordRecipeTypeVariantMemorable(&PasswordRecipeMemorableInner{WordCount: 4}))
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("memorable recipes should stay unsupported until word-list parity is decided")
	}
}

func TestSecretsGeneratePasswordMemorableUnsupported(t *testing.T) {
	_, err := Secrets.GeneratePassword(context.Background(), NewPasswordRecipeTypeVariantMemorable(&PasswordRecipeMemorableInner{WordCount: 4}))
	if err == nil {
		t.Fatal("expected unsupported memorable password error")
	}
	if got, want := err.Error(), "native password recipe is not implemented"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

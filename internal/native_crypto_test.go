package internal

import (
	"bytes"
	"strings"
	"testing"
)

func TestAES256GCMRoundTrip(t *testing.T) {
	keys, err := testServiceAccountCredentials().keyMaterial()
	if err != nil {
		t.Fatal(err)
	}

	nonce := []byte("123456789012")
	additionalData := []byte("aad")
	plaintext := []byte("secret")

	ciphertext, err := aes256GCMSeal(keys.MUK, nonce, plaintext, additionalData)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext unexpectedly equals plaintext")
	}

	got, err := aes256GCMOpen(keys.MUK, nonce, ciphertext, additionalData)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("got plaintext %q, want %q", got, plaintext)
	}
}

func TestAES256GCMOpenRejectsTamperedCiphertext(t *testing.T) {
	keys, err := testServiceAccountCredentials().keyMaterial()
	if err != nil {
		t.Fatal(err)
	}

	nonce := []byte("123456789012")
	ciphertext, err := aes256GCMSeal(keys.MUK, nonce, []byte("secret"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[len(ciphertext)-1] ^= 0xff

	_, err = aes256GCMOpen(keys.MUK, nonce, ciphertext, []byte("aad"))
	if err == nil {
		t.Fatal("expected tampered ciphertext error")
	}
	if !strings.Contains(err.Error(), "decrypt aes-256-gcm payload") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAES256GCMRejectsInvalidInputs(t *testing.T) {
	_, err := aes256GCMSeal([]byte("short"), []byte("123456789012"), []byte("secret"), nil)
	if err == nil {
		t.Fatal("expected short key error")
	}
	if !strings.Contains(err.Error(), "key must be 32 bytes") {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = aes256GCMSeal(bytes.Repeat([]byte{1}, 32), []byte("short"), []byte("secret"), nil)
	if err == nil {
		t.Fatal("expected short nonce error")
	}
	if !strings.Contains(err.Error(), "nonce must be 12 bytes") {
		t.Fatalf("unexpected error: %v", err)
	}
}

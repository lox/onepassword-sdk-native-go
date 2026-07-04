package internal

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestHKDFSHA256(t *testing.T) {
	secret := bytes.Repeat([]byte{0x0b}, 22)
	salt, err := hex.DecodeString("000102030405060708090a0b0c")
	if err != nil {
		t.Fatal(err)
	}
	info, err := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	if err != nil {
		t.Fatal(err)
	}

	key, err := hkdfSHA256(secret, salt, string(info), 42)
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(key)
	want := "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestHKDFSHA256RejectsInvalidKeyLength(t *testing.T) {
	if _, err := hkdfSHA256([]byte("secret"), nil, "", 0); err == nil {
		t.Fatal("expected key length error")
	}
}

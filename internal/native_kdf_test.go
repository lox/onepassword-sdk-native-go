package internal

import (
	"encoding/hex"
	"testing"
)

func TestPBKDF2SHA256(t *testing.T) {
	key, err := pbkdf2SHA256([]byte("password"), []byte("salt"), 1, 32)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(key), "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestPBKDF2SHA256RejectsBadParams(t *testing.T) {
	if _, err := pbkdf2SHA256([]byte("password"), []byte("salt"), 0, 32); err == nil {
		t.Fatal("expected iterations error")
	}
	if _, err := pbkdf2SHA256([]byte("password"), []byte("salt"), 1, 0); err == nil {
		t.Fatal("expected key length error")
	}
}

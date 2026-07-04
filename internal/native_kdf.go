package internal

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
)

func hkdfSHA256(secret, salt []byte, info string, keyLen int) ([]byte, error) {
	if keyLen <= 0 {
		return nil, fmt.Errorf("key length must be greater than zero")
	}
	key, err := hkdf.Key(sha256.New, secret, salt, info, keyLen)
	if err != nil {
		return nil, fmt.Errorf("derive hkdf-sha256 key: %w", err)
	}
	return key, nil
}

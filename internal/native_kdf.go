package internal

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
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

func pbkdf2SHA256(password, salt []byte, iterations uint32, keyLen int) ([]byte, error) {
	if iterations == 0 {
		return nil, fmt.Errorf("iterations must be greater than zero")
	}
	if keyLen <= 0 {
		return nil, fmt.Errorf("key length must be greater than zero")
	}

	hashLen := sha256.Size
	blockCount := (keyLen + hashLen - 1) / hashLen
	out := make([]byte, 0, blockCount*hashLen)
	for block := uint32(1); block <= uint32(blockCount); block++ {
		u := pbkdf2Block(password, salt, block)
		t := append([]byte(nil), u...)
		for i := uint32(1); i < iterations; i++ {
			u = hmacSHA256(password, u)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen], nil
}

func pbkdf2Block(password, salt []byte, block uint32) []byte {
	msg := make([]byte, len(salt)+4)
	copy(msg, salt)
	binary.BigEndian.PutUint32(msg[len(salt):], block)
	return hmacSHA256(password, msg)
}

func hmacSHA256(key, msg []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return mac.Sum(nil)
}

package internal

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func aes256GCMSeal(key, nonce, plaintext, additionalData []byte) ([]byte, error) {
	gcm, err := newAES256GCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("aes-256-gcm nonce must be %d bytes", gcm.NonceSize())
	}
	return gcm.Seal(nil, nonce, plaintext, additionalData), nil
}

func aes256GCMOpen(key, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	gcm, err := newAES256GCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("aes-256-gcm nonce must be %d bytes", gcm.NonceSize())
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("decrypt aes-256-gcm payload: %w", err)
	}
	return plaintext, nil
}

func newAES256GCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("aes-256-gcm key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create aes-gcm cipher: %w", err)
	}
	return gcm, nil
}

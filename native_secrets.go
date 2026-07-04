package onepassword

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
)

const (
	passwordLetters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	passwordDigits  = "0123456789"
	passwordSymbols = "!@#$%^&*_-+=:;,.?"
)

func validateSecretReference(secretReference string) error {
	body, ok := strings.CutPrefix(secretReference, "op://")
	if !ok {
		return errors.New("error validating secret reference: secret reference is not prefixed with \"op://\"")
	}
	if body == "" {
		return errors.New("error validating secret reference: expected op://vault/item/field")
	}

	if strings.Contains(body, "#") {
		return errors.New("error validating secret reference: fragments are not supported")
	}
	pathPart, query, _ := strings.Cut(body, "?")
	if query != "" {
		values, err := url.ParseQuery(query)
		if err != nil {
			return fmt.Errorf("error validating secret reference: %w", err)
		}
		attributes, ok := values["attribute"]
		if len(values) != 1 || !ok {
			return errors.New("error validating secret reference: only the attribute query parameter is supported")
		}
		if len(attributes) != 1 || attributes[0] == "" {
			return errors.New("error validating secret reference: attribute query parameter must have exactly one value")
		}
	}

	parts := strings.Split(pathPart, "/")
	if len(parts) != 3 && len(parts) != 4 {
		return errors.New("error validating secret reference: expected op://vault/item/field or op://vault/item/section/field")
	}
	for _, part := range parts {
		if part == "" {
			return errors.New("error validating secret reference: vault, item, section, and field components cannot be empty")
		}
		decoded, err := url.PathUnescape(part)
		if err != nil {
			return fmt.Errorf("error validating secret reference: %w", err)
		}
		if strings.ContainsAny(decoded, "/?#") {
			return errors.New("error validating secret reference: vault, item, section, and field components cannot contain /, ?, or #")
		}
	}
	return nil
}

func generatePassword(recipe PasswordRecipe) (GeneratePasswordResponse, bool, error) {
	switch recipe.Type {
	case PasswordRecipeTypeVariantPin:
		pin := recipe.Pin()
		if pin == nil {
			return GeneratePasswordResponse{}, true, errors.New("missing PIN password parameters")
		}
		if pin.Length == 0 {
			return GeneratePasswordResponse{}, true, errors.New("password length must be greater than zero")
		}
		password, err := randomString(passwordDigits, int(pin.Length))
		return GeneratePasswordResponse{Password: password}, true, err
	case PasswordRecipeTypeVariantRandom:
		random := recipe.Random()
		if random == nil {
			return GeneratePasswordResponse{}, true, errors.New("missing random password parameters")
		}
		password, err := randomPassword(random)
		return GeneratePasswordResponse{Password: password}, true, err
	default:
		return GeneratePasswordResponse{}, false, nil
	}
}

func randomPassword(recipe *PasswordRecipeRandomInner) (string, error) {
	if recipe.Length == 0 {
		return "", errors.New("password length must be greater than zero")
	}

	charset := passwordLetters
	required := []byte{}
	if recipe.IncludeDigits {
		charset += passwordDigits
		digit, err := randomByte(passwordDigits)
		if err != nil {
			return "", err
		}
		required = append(required, digit)
	}
	if recipe.IncludeSymbols {
		charset += passwordSymbols
		symbol, err := randomByte(passwordSymbols)
		if err != nil {
			return "", err
		}
		required = append(required, symbol)
	}
	if int(recipe.Length) < len(required) {
		return "", fmt.Errorf("password length must be at least %d", len(required))
	}

	rest, err := randomString(charset, int(recipe.Length)-len(required))
	if err != nil {
		return "", err
	}
	password := append(required, []byte(rest)...)
	if err := shuffleBytes(password); err != nil {
		return "", err
	}
	return string(password), nil
}

func randomString(charset string, length int) (string, error) {
	if length == 0 {
		return "", nil
	}
	buf := make([]byte, length)
	for i := range buf {
		b, err := randomByte(charset)
		if err != nil {
			return "", err
		}
		buf[i] = b
	}
	return string(buf), nil
}

func randomByte(charset string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
	if err != nil {
		return 0, err
	}
	return charset[n.Int64()], nil
}

func shuffleBytes(b []byte) error {
	for i := len(b) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return err
		}
		b[i], b[j.Int64()] = b[j.Int64()], b[i]
	}
	return nil
}

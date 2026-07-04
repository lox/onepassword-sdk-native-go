package onepassword

import (
	"errors"
	"fmt"

	"github.com/lox/onepassword-sdk-native-go/internal"
)

const (
	passwordDigits  = "0123456789"
	passwordSymbols = "!@#$%^&*_-+=:;,.?"
)

func validateSecretReference(secretReference string) error {
	if err := internal.ValidateSecretReference(secretReference); err != nil {
		return fmt.Errorf("error validating secret reference: %w", err)
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
		password, err := internal.RandomString(passwordDigits, int(pin.Length))
		return GeneratePasswordResponse{Password: password}, true, err
	case PasswordRecipeTypeVariantRandom:
		random := recipe.Random()
		if random == nil {
			return GeneratePasswordResponse{}, true, errors.New("missing random password parameters")
		}
		password, err := internal.RandomPassword(random.Length, random.IncludeDigits, random.IncludeSymbols)
		return GeneratePasswordResponse{Password: password}, true, err
	default:
		return GeneratePasswordResponse{}, false, nil
	}
}

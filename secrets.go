package onepassword

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/lox/onepassword-sdk-native-go/internal"
)

// The Secrets API includes all operations the SDK client can perform on secrets.
// Use secret reference URIs to securely load secrets from 1Password: `op://<vault-name>/<item-name>[/<section-name>]/<field-name>`
type SecretsAPI interface {
	// Resolve returns the secret the provided secret reference points to.
	Resolve(ctx context.Context, secretReference string) (string, error)

	// Resolve takes in a list of secret references and returns the secrets they point to or errors if any.
	ResolveAll(ctx context.Context, secretReferences []string) (ResolveAllResponse, error)
}

type SecretsSource struct {
	*internal.InnerClient
}

func NewSecretsSource(inner *internal.InnerClient) SecretsAPI {
	return &SecretsSource{InnerClient: inner}
}

type secretsUtil struct{}

var Secrets = secretsUtil{}

// Resolve returns the secret the provided secret reference points to.
func (s SecretsSource) Resolve(ctx context.Context, secretReference string) (string, error) {
	resultString, err := clientInvoke(ctx, s.InnerClient, "SecretsResolve", map[string]interface{}{
		"secret_reference": secretReference,
	})
	if err != nil {
		return "", err
	}
	var result string
	err = json.Unmarshal([]byte(*resultString), &result)
	if err != nil {
		return "", err
	}
	return result, nil
}

// Resolve takes in a list of secret references and returns the secrets they point to or errors if any.
func (s SecretsSource) ResolveAll(ctx context.Context, secretReferences []string) (ResolveAllResponse, error) {
	resultString, err := clientInvoke(ctx, s.InnerClient, "SecretsResolveAll", map[string]interface{}{
		"secret_references": secretReferences,
	})
	if err != nil {
		return ResolveAllResponse{}, err
	}
	var result ResolveAllResponse
	err = json.Unmarshal([]byte(*resultString), &result)
	if err != nil {
		return ResolveAllResponse{}, err
	}
	return result, nil
}

// Validate the secret reference to ensure there are no syntax errors.
func (s secretsUtil) ValidateSecretReference(ctx context.Context, secretReference string) error {
	return validateSecretReference(secretReference)
}

// Generate a password using the provided recipe.
func (s secretsUtil) GeneratePassword(ctx context.Context, recipe PasswordRecipe) (GeneratePasswordResponse, error) {
	if result, ok, err := generatePassword(recipe); ok || err != nil {
		return result, err
	}

	return GeneratePasswordResponse{}, errors.New("native password recipe is not implemented")
}

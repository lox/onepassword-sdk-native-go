package internal

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"sync"
)

type NativeCore struct {
	mu      sync.Mutex
	nextID  uint64
	clients map[uint64]*nativeClient
}

func GetNativeCore() *CoreWrapper {
	return &CoreWrapper{InnerCore: &NativeCore{
		clients: map[uint64]*nativeClient{},
	}}
}

func (c *NativeCore) InitClient(ctx context.Context, config []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var clientConfig ClientConfig
	if err := json.Unmarshal(config, &clientConfig); err != nil {
		return nil, err
	}
	if clientConfig.AccountName == nil && clientConfig.SAToken == "" {
		return nil, fmt.Errorf(`{"name":"InvalidUserInput","message":"invalid user input: encountered the following errors: service account token was not specified"}`)
	}
	creds, err := parseServiceAccountToken(clientConfig.SAToken)
	if clientConfig.AccountName == nil && err != nil {
		return nil, nativeError("InvalidUserInput", fmt.Sprintf("invalid service account token: %v", err))
	}
	client, err := newNativeClient(clientConfig, creds)
	if err != nil {
		return nil, nativeError("InvalidUserInput", err.Error())
	}

	c.mu.Lock()
	id := c.nextID
	c.nextID++
	c.clients[id] = client
	c.mu.Unlock()

	return json.Marshal(id)
}

func (c *NativeCore) Invoke(ctx context.Context, invokeConfig []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var invocation InvokeConfig
	if err := json.Unmarshal(invokeConfig, &invocation); err != nil {
		return nil, err
	}

	if response, handled, err := c.invokeNative(ctx, invocation); handled || err != nil {
		return response, err
	}

	return nil, unsupportedNativeMethodError(invocation.Invocation.Parameters.MethodName)
}

func (c *NativeCore) invokeNative(ctx context.Context, invocation InvokeConfig) ([]byte, bool, error) {
	switch invocation.Invocation.Parameters.MethodName {
	case "ValidateSecretReference":
		ref, err := stringParam(invocation.Invocation.Parameters.SerializedParams, "secret_reference")
		if err != nil {
			return nil, true, nativeError("InvalidUserInput", err.Error())
		}
		if err := validateSecretReference(ref); err != nil {
			return nil, true, nativeError("Validation", err.Error())
		}
		return []byte("null"), true, nil
	case "GeneratePassword":
		response, handled, err := generatePassword(invocation.Invocation.Parameters.SerializedParams)
		return response, handled, err
	default:
		if response, handled, err := c.invokeNativeSecret(ctx, invocation); handled || err != nil {
			return response, handled, err
		}
		if response, handled, err := c.invokeNativeInventory(ctx, invocation); handled || err != nil {
			return response, handled, err
		}
		return c.invokeNativeItem(ctx, invocation)
	}
}

func (c *NativeCore) ReleaseClient(clientID []byte) {
	var id uint64
	if err := json.Unmarshal(clientID, &id); err != nil {
		return
	}

	c.mu.Lock()
	delete(c.clients, id)
	c.mu.Unlock()
}

func (c *NativeCore) client(id uint64) (*nativeClient, error) {
	c.mu.Lock()
	client := c.clients[id]
	c.mu.Unlock()

	if client == nil {
		return nil, fmt.Errorf(`{"name":"Internal","message":"invalid client id"}`)
	}
	return client, nil
}

func unsupportedNativeMethodError(method string) error {
	return nativeError("UnsupportedNativeMethod", fmt.Sprintf("native core does not implement %q", method))
}

func nativeError(name, message string) error {
	payload, err := json.Marshal(struct {
		Name    string `json:"name"`
		Message string `json:"message"`
	}{Name: name, Message: message})
	if err != nil {
		return err
	}
	return fmt.Errorf("%s", payload)
}

func nativeErrorName(err error) string {
	if err == nil {
		return ""
	}
	var payload struct {
		Name string `json:"name"`
	}
	if json.Unmarshal([]byte(err.Error()), &payload) != nil {
		return ""
	}
	return payload.Name
}

func stringParam(params map[string]interface{}, name string) (string, error) {
	value, ok := params[name]
	if !ok {
		return "", fmt.Errorf("missing parameter %q", name)
	}
	s, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("parameter %q must be a string", name)
	}
	return s, nil
}

func validateSecretReference(secretReference string) error {
	body, ok := strings.CutPrefix(secretReference, "op://")
	if !ok {
		return errors.New("secret reference is not prefixed with \"op://\"")
	}
	if body == "" {
		return errors.New("expected op://vault/item/field")
	}

	if strings.Contains(body, "#") {
		return errors.New("fragments are not supported")
	}
	pathPart, query, _ := strings.Cut(body, "?")
	if query != "" {
		values, err := url.ParseQuery(query)
		if err != nil {
			return err
		}
		attributes, ok := values["attribute"]
		if len(values) != 1 || !ok {
			return errors.New("only the attribute query parameter is supported")
		}
		if len(attributes) != 1 || attributes[0] == "" {
			return errors.New("attribute query parameter must have exactly one value")
		}
	}

	parts := strings.Split(pathPart, "/")
	if len(parts) != 3 && len(parts) != 4 {
		return errors.New("expected op://vault/item/field or op://vault/item/section/field")
	}
	for _, part := range parts {
		if part == "" {
			return errors.New("vault, item, section, and field components cannot be empty")
		}
		decoded, err := url.PathUnescape(part)
		if err != nil {
			return err
		}
		if strings.ContainsAny(decoded, "/?#") {
			return errors.New("vault, item, section, and field components cannot contain /, ?, or #")
		}
	}
	return nil
}

func generatePassword(params map[string]interface{}) ([]byte, bool, error) {
	recipe, ok := params["recipe"].(map[string]interface{})
	if !ok {
		return nil, true, nativeError("InvalidUserInput", `parameter "recipe" must be an object`)
	}
	recipeType, ok := recipe["type"].(string)
	if !ok {
		return nil, true, nativeError("InvalidUserInput", `parameter "recipe.type" must be a string`)
	}
	recipeParams, ok := recipe["parameters"].(map[string]interface{})
	if !ok {
		return nil, true, nativeError("InvalidUserInput", `parameter "recipe.parameters" must be an object`)
	}

	var password string
	var err error
	switch recipeType {
	case "Pin":
		password, err = generatePIN(recipeParams)
	case "Random":
		password, err = generateRandomPassword(recipeParams)
	default:
		return nil, false, nil
	}
	if err != nil {
		return nil, true, nativeError("InvalidUserInput", err.Error())
	}

	response, err := json.Marshal(struct {
		Password string `json:"password"`
	}{Password: password})
	return response, true, err
}

func generatePIN(params map[string]interface{}) (string, error) {
	length, err := uintParam(params, "length")
	if err != nil {
		return "", err
	}
	if length == 0 {
		return "", errors.New("password length must be greater than zero")
	}
	return randomString("0123456789", int(length))
}

func generateRandomPassword(params map[string]interface{}) (string, error) {
	length, err := uintParam(params, "length")
	if err != nil {
		return "", err
	}
	if length == 0 {
		return "", errors.New("password length must be greater than zero")
	}
	includeDigits, err := boolParam(params, "includeDigits")
	if err != nil {
		return "", err
	}
	includeSymbols, err := boolParam(params, "includeSymbols")
	if err != nil {
		return "", err
	}

	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	const digits = "0123456789"
	const symbols = "!@#$%^&*_-+=:;,.?"

	charset := letters
	required := []byte{}
	if includeDigits {
		charset += digits
		digit, err := randomByte(digits)
		if err != nil {
			return "", err
		}
		required = append(required, digit)
	}
	if includeSymbols {
		charset += symbols
		symbol, err := randomByte(symbols)
		if err != nil {
			return "", err
		}
		required = append(required, symbol)
	}
	if int(length) < len(required) {
		return "", fmt.Errorf("password length must be at least %d", len(required))
	}

	rest, err := randomString(charset, int(length)-len(required))
	if err != nil {
		return "", err
	}
	password := append(required, []byte(rest)...)
	if err := shuffleBytes(password); err != nil {
		return "", err
	}
	return string(password), nil
}

func uintParam(params map[string]interface{}, name string) (uint32, error) {
	value, ok := params[name]
	if !ok {
		return 0, fmt.Errorf("missing parameter %q", name)
	}
	switch v := value.(type) {
	case float64:
		if v < 0 || v != float64(uint32(v)) {
			return 0, fmt.Errorf("parameter %q must be a non-negative integer", name)
		}
		return uint32(v), nil
	case uint32:
		return v, nil
	case int:
		if v < 0 {
			return 0, fmt.Errorf("parameter %q must be a non-negative integer", name)
		}
		return uint32(v), nil
	default:
		return 0, fmt.Errorf("parameter %q must be a number", name)
	}
}

func boolParam(params map[string]interface{}, name string) (bool, error) {
	value, ok := params[name]
	if !ok {
		return false, fmt.Errorf("missing parameter %q", name)
	}
	b, ok := value.(bool)
	if !ok {
		return false, fmt.Errorf("parameter %q must be a boolean", name)
	}
	return b, nil
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

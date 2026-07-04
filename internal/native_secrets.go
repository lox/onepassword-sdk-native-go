package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

func (c *NativeCore) invokeNativeSecret(ctx context.Context, invocation InvokeConfig) ([]byte, bool, error) {
	method := invocation.Invocation.Parameters.MethodName
	params := invocation.Invocation.Parameters.SerializedParams

	switch method {
	case "SecretsResolve":
		request, err := nativeSecretResolveRequest(params)
		if err != nil {
			return nil, true, nativeError("InvalidUserInput", err.Error())
		}
		client, err := c.nativeSecretClient(invocation)
		if err != nil {
			return nil, true, err
		}
		response, err := client.resolveSecret(ctx, request)
		return response, true, err
	case "SecretsResolveAll":
		request, err := nativeSecretResolveAllRequest(params)
		if err != nil {
			return nil, true, nativeError("InvalidUserInput", err.Error())
		}
		client, err := c.nativeSecretClient(invocation)
		if err != nil {
			return nil, true, err
		}
		response, err := client.resolveSecrets(ctx, request)
		return response, true, err
	default:
		return nil, false, nil
	}
}

func (c *NativeCore) nativeSecretClient(invocation InvokeConfig) (*nativeClient, error) {
	if invocation.Invocation.ClientID == nil {
		return nil, nativeError("Internal", "native secret method requires a client id")
	}
	return c.client(*invocation.Invocation.ClientID)
}

type nativeSecretResolveParams struct {
	SecretReference string                `json:"secret_reference"`
	Reference       nativeSecretReference `json:"-"`
}

type nativeSecretResolveAllParams struct {
	SecretReferences []string                `json:"secret_references"`
	References       []nativeSecretReference `json:"-"`
}

type nativeSecretReference struct {
	Vault     string
	Item      string
	Section   string
	Field     string
	Attribute string
}

type nativeResolvedReference struct {
	Secret  string `json:"secret"`
	ItemID  string `json:"itemId"`
	VaultID string `json:"vaultId"`
}

type nativeResolveAllResponse struct {
	IndividualResponses map[string]nativeResolveReferenceResponse `json:"individualResponses"`
}

type nativeResolveReferenceResponse struct {
	Content *nativeResolvedReference `json:"content,omitempty"`
	Error   *nativeResolveError      `json:"error,omitempty"`
}

type nativeResolveError struct {
	Type    string `json:"type"`
	Message string `json:"message,omitempty"`
}

func nativeSecretResolveRequest(params map[string]interface{}) (nativeSecretResolveParams, error) {
	ref, err := stringParam(params, "secret_reference")
	if err != nil {
		return nativeSecretResolveParams{}, err
	}
	parsed, err := parseNativeSecretReference(ref)
	if err != nil {
		return nativeSecretResolveParams{}, err
	}
	return nativeSecretResolveParams{SecretReference: ref, Reference: parsed}, nil
}

func nativeSecretResolveAllRequest(params map[string]interface{}) (nativeSecretResolveAllParams, error) {
	if _, ok := params["secret_references"]; !ok {
		return nativeSecretResolveAllParams{}, fmt.Errorf("missing parameter %q", "secret_references")
	}
	var request nativeSecretResolveAllParams
	if err := decodeNativeParams(params, &request); err != nil {
		return nativeSecretResolveAllParams{}, err
	}
	if len(request.SecretReferences) == 0 {
		return nativeSecretResolveAllParams{}, fmt.Errorf("parameter %q cannot be empty", "secret_references")
	}
	for i, ref := range request.SecretReferences {
		parsed, err := parseNativeSecretReference(ref)
		if err != nil {
			return nativeSecretResolveAllParams{}, fmt.Errorf("secret_references[%d]: %w", i, err)
		}
		request.References = append(request.References, parsed)
	}
	return request, nil
}

func parseNativeSecretReference(secretReference string) (nativeSecretReference, error) {
	if err := validateSecretReference(secretReference); err != nil {
		return nativeSecretReference{}, err
	}

	body := mustCutPrefix(secretReference, "op://")
	pathPart, rawQuery, _ := strings.Cut(body, "?")
	parts := strings.Split(pathPart, "/")
	decoded := make([]string, 0, len(parts))
	for _, part := range parts {
		value, err := url.PathUnescape(part)
		if err != nil {
			return nativeSecretReference{}, err
		}
		decoded = append(decoded, value)
	}

	ref := nativeSecretReference{
		Vault: decoded[0],
		Item:  decoded[1],
	}
	if len(decoded) == 3 {
		ref.Field = decoded[2]
	} else {
		ref.Section = decoded[2]
		ref.Field = decoded[3]
	}
	if rawQuery != "" {
		values, err := url.ParseQuery(rawQuery)
		if err != nil {
			return nativeSecretReference{}, err
		}
		ref.Attribute = values.Get("attribute")
	}
	return ref, nil
}

func nativeSecretValueFromItem(item nativeItemResponse, ref nativeSecretReference) (string, error) {
	matches, err := nativeSecretMatchingFields(item, ref)
	if err != nil {
		return "", err
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("field not found")
	case 1:
		return nativeSecretValueFromField(matches[0], ref)
	default:
		return "", fmt.Errorf("too many matching fields")
	}
}

func nativeSecretMatchingFields(item nativeItemResponse, ref nativeSecretReference) ([]nativeItemField, error) {
	var fields []nativeItemField
	if len(item.Fields) == 0 {
		return nil, fmt.Errorf("field not found")
	}
	if err := json.Unmarshal(item.Fields, &fields); err != nil {
		return nil, fmt.Errorf("decode item fields: %w", err)
	}

	sectionID := ""
	if ref.Section != "" {
		var ok bool
		sectionID, ok = nativeItemSectionID(item, ref.Section)
		if !ok {
			return nil, fmt.Errorf("section not found")
		}
	}

	matches := make([]nativeItemField, 0, 1)
	for _, field := range fields {
		if field.ID != ref.Field && field.Title != ref.Field {
			continue
		}
		if sectionID != "" {
			if field.SectionID == nil || *field.SectionID != sectionID {
				continue
			}
		}
		matches = append(matches, field)
	}
	return matches, nil
}

func nativeSecretValueFromField(field nativeItemField, ref nativeSecretReference) (string, error) {
	switch ref.Attribute {
	case "":
		return field.Value, nil
	case "totp":
		return nativeTOTPValueFromField(field)
	default:
		return "", fmt.Errorf("secret reference attribute %q is not implemented", ref.Attribute)
	}
}

func nativeTOTPValueFromField(field nativeItemField) (string, error) {
	if field.FieldType != "Totp" {
		return "", errNativeResolve("incompatibleTOTPQueryParameterField")
	}
	if field.Details == nil || field.Details.Type != "Otp" {
		return "", errNativeResolve("unableToGenerateTotpCode")
	}
	var details struct {
		Code         *string `json:"code,omitempty"`
		ErrorMessage *string `json:"errorMessage,omitempty"`
	}
	if err := json.Unmarshal(field.Details.Content, &details); err != nil {
		return "", fmt.Errorf("decode totp field details: %w", err)
	}
	if details.Code != nil && *details.Code != "" {
		return *details.Code, nil
	}
	return "", errNativeResolve("unableToGenerateTotpCode")
}

func nativeItemSectionID(item nativeItemResponse, section string) (string, bool) {
	if len(item.Sections) == 0 {
		return "", false
	}
	var sections []nativeItemSection
	if err := json.Unmarshal(item.Sections, &sections); err != nil {
		return "", false
	}
	for _, candidate := range sections {
		if candidate.ID == section || candidate.Title == section {
			return candidate.ID, true
		}
	}
	return "", false
}

func mustCutPrefix(s, prefix string) string {
	trimmed, _ := strings.CutPrefix(s, prefix)
	return trimmed
}

func (c *nativeClient) resolveSecret(ctx context.Context, request nativeSecretResolveParams) ([]byte, error) {
	resolved, resolveErr := c.resolveReference(ctx, request.Reference)
	if resolveErr != nil {
		if isNativeMethodNotImplemented(resolveErr) {
			return nil, resolveErr
		}
		return nil, nativeError("ResolvingSecretReference", resolveErr.Error())
	}
	return json.Marshal(resolved.Secret)
}

func (c *nativeClient) resolveSecrets(ctx context.Context, request nativeSecretResolveAllParams) ([]byte, error) {
	if err := c.ensureSession(ctx); err != nil {
		return nil, err
	}
	response := nativeResolveAllResponse{IndividualResponses: map[string]nativeResolveReferenceResponse{}}
	for i, ref := range request.References {
		resolved, err := c.resolveReference(ctx, ref)
		if err != nil {
			response.IndividualResponses[request.SecretReferences[i]] = nativeResolveReferenceResponse{
				Error: nativeResolveErrorFromError(err),
			}
			continue
		}
		response.IndividualResponses[request.SecretReferences[i]] = nativeResolveReferenceResponse{Content: &resolved}
	}
	return json.Marshal(response)
}

func (c *nativeClient) resolveReference(ctx context.Context, ref nativeSecretReference) (nativeResolvedReference, error) {
	if err := c.ensureSession(ctx); err != nil {
		return nativeResolvedReference{}, err
	}
	vault, err := c.resolveVault(ctx, ref.Vault)
	if err != nil {
		return nativeResolvedReference{}, err
	}
	item, err := c.resolveItem(ctx, vault.ID, ref.Item)
	if err != nil {
		return nativeResolvedReference{}, err
	}
	secret, err := nativeSecretValueFromItem(item, ref)
	if err != nil {
		return nativeResolvedReference{}, err
	}
	return nativeResolvedReference{Secret: secret, ItemID: item.ID, VaultID: vault.ID}, nil
}

type nativeVaultOverview struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

func (c *nativeClient) resolveVault(ctx context.Context, vaultRef string) (nativeVaultOverview, error) {
	if isNativeObjectID(vaultRef) {
		return nativeVaultOverview{ID: vaultRef}, nil
	}
	response, err := c.listVaults(ctx, nativeVaultsListParams{})
	if err != nil {
		return nativeVaultOverview{}, err
	}
	var vaults []nativeVaultOverview
	if err := json.Unmarshal(response, &vaults); err != nil {
		return nativeVaultOverview{}, fmt.Errorf("decode vault list: %w", err)
	}
	var matches []nativeVaultOverview
	for _, vault := range vaults {
		if vault.ID == vaultRef || vault.Title == vaultRef {
			matches = append(matches, vault)
		}
	}
	switch len(matches) {
	case 0:
		return nativeVaultOverview{}, errNativeResolve("vaultNotFound")
	case 1:
		return matches[0], nil
	default:
		return nativeVaultOverview{}, errNativeResolve("tooManyVaults")
	}
}

func (c *nativeClient) resolveItem(ctx context.Context, vaultID, itemRef string) (nativeItemResponse, error) {
	if isNativeObjectID(itemRef) {
		return c.getItemResponse(ctx, nativeVaultItemParams{VaultID: vaultID, ItemID: itemRef})
	}
	response, err := c.listItems(ctx, nativeItemsListParams{VaultID: vaultID})
	if err != nil {
		return nativeItemResponse{}, err
	}
	var overviews []nativeItemOverview
	if err := json.Unmarshal(response, &overviews); err != nil {
		return nativeItemResponse{}, fmt.Errorf("decode item list: %w", err)
	}
	var matches []nativeItemOverview
	for _, item := range overviews {
		if item.ID == itemRef || item.Title == itemRef {
			matches = append(matches, item)
		}
	}
	switch len(matches) {
	case 0:
		return nativeItemResponse{}, errNativeResolve("itemNotFound")
	case 1:
		return c.getItemResponse(ctx, nativeVaultItemParams{VaultID: vaultID, ItemID: matches[0].ID})
	default:
		return nativeItemResponse{}, errNativeResolve("tooManyItems")
	}
}

type nativeResolveErr string

func errNativeResolve(kind string) error {
	return nativeResolveErr(kind)
}

func (e nativeResolveErr) Error() string {
	return string(e)
}

func nativeResolveErrorFromError(err error) *nativeResolveError {
	if err == nil {
		return nil
	}
	if kind, ok := err.(nativeResolveErr); ok {
		return &nativeResolveError{Type: string(kind)}
	}
	switch err.Error() {
	case "field not found":
		return &nativeResolveError{Type: "fieldNotFound"}
	case "too many matching fields":
		return &nativeResolveError{Type: "tooManyMatchingFields"}
	case "section not found":
		return &nativeResolveError{Type: "noMatchingSections"}
	default:
		return &nativeResolveError{Type: "other", Message: err.Error()}
	}
}

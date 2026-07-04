package internal

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func (c *NativeCore) invokeNativeItem(ctx context.Context, invocation InvokeConfig) ([]byte, bool, error) {
	method := invocation.Invocation.Parameters.MethodName
	params := invocation.Invocation.Parameters.SerializedParams
	if !nativeItemMethod(method) {
		return nil, false, nil
	}

	switch method {
	case "ItemsList":
		request, err := nativeItemsListRequest(params)
		if err != nil {
			return nil, true, nativeError("InvalidUserInput", err.Error())
		}
		client, err := c.nativeItemClient(invocation)
		if err != nil {
			return nil, true, err
		}
		response, err := client.listItems(ctx, request)
		return response, true, err
	case "ItemsGet", "ItemsDelete", "ItemsArchive":
		request, err := nativeVaultItemRequest(params)
		if err != nil {
			return nil, true, nativeError("InvalidUserInput", err.Error())
		}
		client, err := c.nativeItemClient(invocation)
		if err != nil {
			return nil, true, err
		}
		if method == "ItemsDelete" {
			response, err := client.deleteItem(ctx, request)
			return response, true, err
		}
		if method == "ItemsArchive" {
			response, err := client.archiveItem(request)
			return response, true, err
		}
		response, err := client.getItem(ctx, request)
		return response, true, err
	case "ItemsGetAll", "ItemsDeleteAll":
		request, err := nativeVaultItemsRequest(params)
		if err != nil {
			return nil, true, nativeError("InvalidUserInput", err.Error())
		}
		client, err := c.nativeItemClient(invocation)
		if err != nil {
			return nil, true, err
		}
		if method == "ItemsDeleteAll" {
			response, err := client.deleteItems(ctx, request)
			return response, true, err
		}
		response, err := client.getItems(ctx, request)
		return response, true, err
	case "ItemsCreate":
		request, err := nativeItemCreateRequest(params)
		if err != nil {
			return nil, true, nativeError("InvalidUserInput", err.Error())
		}
		client, err := c.nativeItemClient(invocation)
		if err != nil {
			return nil, true, err
		}
		response, err := client.createItem(ctx, request)
		return response, true, err
	case "ItemsPut":
		request, err := nativeItemPutRequest(params)
		if err != nil {
			return nil, true, nativeError("InvalidUserInput", err.Error())
		}
		client, err := c.nativeItemClient(invocation)
		if err != nil {
			return nil, true, err
		}
		response, err := client.putItem(ctx, request)
		return response, true, err
	case "ItemsCreateAll":
		request, err := nativeItemCreateAllRequest(params)
		if err != nil {
			return nil, true, nativeError("InvalidUserInput", err.Error())
		}
		client, err := c.nativeItemClient(invocation)
		if err != nil {
			return nil, true, err
		}
		response, err := client.createItems(ctx, request)
		return response, true, err
	}
	return nil, false, nil
}

func (c *NativeCore) nativeItemClient(invocation InvokeConfig) (*nativeClient, error) {
	if invocation.Invocation.ClientID == nil {
		return nil, nativeError("Internal", "native item method requires a client id")
	}
	return c.client(*invocation.Invocation.ClientID)
}

func nativeItemMethod(method string) bool {
	switch method {
	case "ItemsList", "ItemsGet", "ItemsGetAll", "ItemsCreate", "ItemsCreateAll", "ItemsPut", "ItemsDelete", "ItemsDeleteAll", "ItemsArchive":
		return true
	default:
		return false
	}
}

type nativeItemsListParams struct {
	VaultID string                 `json:"vault_id"`
	Filters []nativeItemListFilter `json:"filters"`
}

type nativeVaultItemParams struct {
	VaultID string `json:"vault_id"`
	ItemID  string `json:"item_id"`
}

type nativeVaultItemsParams struct {
	VaultID string   `json:"vault_id"`
	ItemIDs []string `json:"item_ids"`
}

type nativeItemCreateParams struct {
	Params nativeItemObject `json:"params"`
}

type nativeItemCreateAllParams struct {
	VaultID string             `json:"vault_id"`
	Params  []nativeItemObject `json:"params"`
}

type nativeItemPutParams struct {
	Item nativeItemObject `json:"item"`
}

type nativeItemObject struct {
	ID      string
	VaultID string
	Fields  []nativeItemField
	Raw     json.RawMessage
}

func (o *nativeItemObject) UnmarshalJSON(data []byte) error {
	var fields struct {
		ID      string            `json:"id"`
		VaultID string            `json:"vaultId"`
		Fields  []nativeItemField `json:"fields"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	o.ID = fields.ID
	o.VaultID = fields.VaultID
	o.Fields = fields.Fields
	o.Raw = append(o.Raw[:0], data...)
	return nil
}

func nativeItemsListRequest(params map[string]interface{}) (nativeItemsListParams, error) {
	if _, ok := params["vault_id"]; !ok {
		return nativeItemsListParams{}, fmt.Errorf("missing parameter %q", "vault_id")
	}
	var request nativeItemsListParams
	if err := decodeNativeParams(params, &request); err != nil {
		return nativeItemsListParams{}, err
	}
	if err := validateNativeObjectID("vault_id", request.VaultID); err != nil {
		return nativeItemsListParams{}, err
	}
	return request, nil
}

func nativeVaultItemRequest(params map[string]interface{}) (nativeVaultItemParams, error) {
	if _, ok := params["vault_id"]; !ok {
		return nativeVaultItemParams{}, fmt.Errorf("missing parameter %q", "vault_id")
	}
	if _, ok := params["item_id"]; !ok {
		return nativeVaultItemParams{}, fmt.Errorf("missing parameter %q", "item_id")
	}
	var request nativeVaultItemParams
	if err := decodeNativeParams(params, &request); err != nil {
		return nativeVaultItemParams{}, err
	}
	if err := validateNativeObjectID("vault_id", request.VaultID); err != nil {
		return nativeVaultItemParams{}, err
	}
	if err := validateNativeObjectID("item_id", request.ItemID); err != nil {
		return nativeVaultItemParams{}, err
	}
	return request, nil
}

func nativeVaultItemsRequest(params map[string]interface{}) (nativeVaultItemsParams, error) {
	if _, ok := params["vault_id"]; !ok {
		return nativeVaultItemsParams{}, fmt.Errorf("missing parameter %q", "vault_id")
	}
	if _, ok := params["item_ids"]; !ok {
		return nativeVaultItemsParams{}, fmt.Errorf("missing parameter %q", "item_ids")
	}
	var request nativeVaultItemsParams
	if err := decodeNativeParams(params, &request); err != nil {
		return nativeVaultItemsParams{}, err
	}
	if err := validateNativeObjectID("vault_id", request.VaultID); err != nil {
		return nativeVaultItemsParams{}, err
	}
	if len(request.ItemIDs) == 0 {
		return nativeVaultItemsParams{}, fmt.Errorf("parameter %q cannot be empty", "item_ids")
	}
	for i, itemID := range request.ItemIDs {
		if err := validateNativeObjectID(fmt.Sprintf("item_ids[%d]", i), itemID); err != nil {
			return nativeVaultItemsParams{}, err
		}
	}
	return request, nil
}

func nativeItemCreateRequest(params map[string]interface{}) (nativeItemCreateParams, error) {
	if _, ok := params["params"]; !ok {
		return nativeItemCreateParams{}, fmt.Errorf("missing parameter %q", "params")
	}
	var request nativeItemCreateParams
	if err := decodeNativeParams(params, &request); err != nil {
		return nativeItemCreateParams{}, err
	}
	if err := validateNativeObjectID("vaultId", request.Params.VaultID); err != nil {
		return nativeItemCreateParams{}, err
	}
	if err := validateNativeItemFields(request.Params.Fields); err != nil {
		return nativeItemCreateParams{}, err
	}
	return request, nil
}

func nativeItemCreateAllRequest(params map[string]interface{}) (nativeItemCreateAllParams, error) {
	if _, ok := params["vault_id"]; !ok {
		return nativeItemCreateAllParams{}, fmt.Errorf("missing parameter %q", "vault_id")
	}
	if _, ok := params["params"]; !ok {
		return nativeItemCreateAllParams{}, fmt.Errorf("missing parameter %q", "params")
	}
	var request nativeItemCreateAllParams
	if err := decodeNativeParams(params, &request); err != nil {
		return nativeItemCreateAllParams{}, err
	}
	if err := validateNativeObjectID("vault_id", request.VaultID); err != nil {
		return nativeItemCreateAllParams{}, err
	}
	if len(request.Params) == 0 {
		return nativeItemCreateAllParams{}, fmt.Errorf("parameter %q cannot be empty", "params")
	}
	for i, item := range request.Params {
		if item.VaultID != "" && item.VaultID != request.VaultID {
			return nativeItemCreateAllParams{}, fmt.Errorf("params[%d].vaultId must match vault_id", i)
		}
		if err := validateNativeItemFields(item.Fields); err != nil {
			return nativeItemCreateAllParams{}, fmt.Errorf("params[%d]: %w", i, err)
		}
	}
	return request, nil
}

func nativeItemPutRequest(params map[string]interface{}) (nativeItemPutParams, error) {
	if _, ok := params["item"]; !ok {
		return nativeItemPutParams{}, fmt.Errorf("missing parameter %q", "item")
	}
	var request nativeItemPutParams
	if err := decodeNativeParams(params, &request); err != nil {
		return nativeItemPutParams{}, err
	}
	if err := validateNativeObjectID("vaultId", request.Item.VaultID); err != nil {
		return nativeItemPutParams{}, err
	}
	if err := validateNativeObjectID("id", request.Item.ID); err != nil {
		return nativeItemPutParams{}, err
	}
	if err := validateNativeItemFields(request.Item.Fields); err != nil {
		return nativeItemPutParams{}, err
	}
	return request, nil
}

func decodeNativeParams(params map[string]interface{}, out interface{}) error {
	b, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("marshal native item parameters: %w", err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		return err
	}
	return nil
}

func validateNativeObjectID(name, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("parameter %q cannot be empty", name)
	}
	if !isNativeObjectID(value) {
		return fmt.Errorf("parameter %q must be a 26-character 1Password ID", name)
	}
	return nil
}

func isNativeObjectID(value string) bool {
	if len(value) != 26 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}

type nativeItemListFilter struct {
	Type    string                    `json:"type"`
	Content nativeItemListFilterState `json:"content"`
}

type nativeItemListFilterState struct {
	Active   bool `json:"active"`
	Archived bool `json:"archived"`
}

type nativeItemOverview struct {
	ID        string          `json:"id"`
	Title     string          `json:"title"`
	Category  string          `json:"category"`
	VaultID   string          `json:"vaultId"`
	Websites  json.RawMessage `json:"websites,omitempty"`
	Tags      []string        `json:"tags"`
	CreatedAt json.RawMessage `json:"createdAt,omitempty"`
	UpdatedAt json.RawMessage `json:"updatedAt,omitempty"`
	State     string          `json:"state"`
}

type nativeEncryptedItemData struct {
	UUID         string             `json:"uuid"`
	Type         string             `json:"type"`
	ItemVersion  uint32             `json:"itemVersion"`
	EncOverview  nativeEncryptedJWK `json:"encOverview"`
	EncDetails   nativeEncryptedJWK `json:"encDetails"`
	EncryptedBy  string             `json:"encryptedBy"`
	VaultKeySN   int                `json:"vaultKeySN"`
	Trashed      string             `json:"trashed"`
	TemplateUUID string             `json:"templateUuid"`
	CreatedAt    json.RawMessage    `json:"createdAt,omitempty"`
	UpdatedAt    json.RawMessage    `json:"updatedAt,omitempty"`
}

type nativeEncryptedItemDetailsResponse struct {
	Item nativeEncryptedItemData `json:"item"`
}

type nativeEncryptedItemOverviewsResponse struct {
	Items            []nativeEncryptedItemData `json:"items"`
	BatchComplete    bool                      `json:"batchComplete"`
	DeletedItemUUIDs []string                  `json:"deletedItemUuids"`
}

type nativeItemResponse struct {
	ID        string          `json:"id"`
	Title     string          `json:"title"`
	Category  string          `json:"category"`
	VaultID   string          `json:"vaultId"`
	Fields    json.RawMessage `json:"fields,omitempty"`
	Sections  json.RawMessage `json:"sections,omitempty"`
	Notes     string          `json:"notes"`
	Tags      []string        `json:"tags"`
	Websites  json.RawMessage `json:"websites,omitempty"`
	Version   uint32          `json:"version"`
	Files     json.RawMessage `json:"files,omitempty"`
	Document  json.RawMessage `json:"document,omitempty"`
	CreatedAt json.RawMessage `json:"createdAt,omitempty"`
	UpdatedAt json.RawMessage `json:"updatedAt,omitempty"`
}

type nativeItemsGetAllResponse struct {
	IndividualResponses []nativeItemGetAllResponse `json:"individualResponses"`
}

type nativeItemsDeleteAllResponse struct {
	IndividualResponses map[string]nativeItemDeleteAllResponse `json:"individualResponses"`
}

type nativeItemsUpdateAllResponse struct {
	IndividualResponses []nativeItemUpdateAllResponse `json:"individualResponses"`
}

type nativePatchVaultItemsResponse struct {
	ContentVersion uint64                    `json:"contentVersion"`
	UpdatedItems   []nativeEncryptedItemData `json:"updatedItems"`
	FailedItems    []nativePatchItemFailure  `json:"failedItems"`
}

type nativePatchVaultItemsRequest struct {
	ContentVersion uint64                    `json:"contentVersion"`
	Items          []nativeEncryptedItemData `json:"items"`
}

type nativePatchItemFailure struct {
	UUID     string                        `json:"uuid"`
	ItemUUID string                        `json:"itemUuid,omitempty"`
	Reason   string                        `json:"reason"`
	Message  string                        `json:"message,omitempty"`
	Error    *nativeItemUpdateFailureError `json:"error,omitempty"`
}

type nativeItemGetAllResponse struct {
	Content *nativeItemResponse   `json:"content,omitempty"`
	Error   *nativeItemsGetAllErr `json:"error,omitempty"`
}

type nativeItemDeleteAllResponse struct {
	Content *struct{}                     `json:"content,omitempty"`
	Error   *nativeItemUpdateFailureError `json:"error,omitempty"`
}

type nativeItemUpdateAllResponse struct {
	Content *nativeItemResponse           `json:"content,omitempty"`
	Error   *nativeItemUpdateFailureError `json:"error,omitempty"`
}

type nativeItemsGetAllErr struct {
	Type    string `json:"type"`
	Message string `json:"message,omitempty"`
}

type nativeItemUpdateFailureError struct {
	Type    string `json:"type"`
	Message string `json:"message,omitempty"`
}

type nativeItemField struct {
	ID        string                  `json:"id"`
	Title     string                  `json:"title"`
	SectionID *string                 `json:"sectionId,omitempty"`
	FieldType string                  `json:"fieldType"`
	Value     string                  `json:"value"`
	Details   *nativeItemFieldDetails `json:"details,omitempty"`
}

type nativeItemFieldDetails struct {
	Type    string          `json:"type"`
	Content json.RawMessage `json:"content"`
}

type nativeItemSection struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

func validateNativeItemFields(fields []nativeItemField) error {
	seen := map[string]struct{}{}
	for _, field := range fields {
		if strings.TrimSpace(field.ID) == "" {
			continue
		}
		if _, ok := seen[field.ID]; ok {
			return fmt.Errorf("item field id %q is duplicated", field.ID)
		}
		seen[field.ID] = struct{}{}
	}
	return nil
}

func (f *nativeItemListFilter) UnmarshalJSON(data []byte) error {
	var raw struct {
		Type    string          `json:"type"`
		Content json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.Type != "ByState" {
		return fmt.Errorf("unsupported item list filter %q", raw.Type)
	}
	var content nativeItemListFilterState
	if err := json.Unmarshal(raw.Content, &content); err != nil {
		return err
	}
	*f = nativeItemListFilter{Type: raw.Type, Content: content}
	return nil
}

func nativeItemStateAllowed(filters []nativeItemListFilter, state string) bool {
	if len(filters) == 0 {
		return true
	}
	if state == "" {
		state = "active"
	}
	for _, filter := range filters {
		switch state {
		case "active":
			if filter.Content.Active {
				return true
			}
		case "archived":
			if filter.Content.Archived {
				return true
			}
		}
	}
	return false
}

func nativeEncodeItemOverviews(items []nativeItemOverview, filters []nativeItemListFilter) ([]byte, error) {
	filtered := make([]nativeItemOverview, 0, len(items))
	for _, item := range items {
		if nativeItemStateAllowed(filters, item.State) {
			item.Category = nativeItemCategory(item.Category)
			item.State = firstNonEmpty(item.State, "active")
			filtered = append(filtered, item)
		}
	}
	response, err := json.Marshal(filtered)
	if err != nil {
		return nil, fmt.Errorf("serialize item overviews: %w", err)
	}
	return response, nil
}

func nativeEncodeItem(item nativeItemResponse) ([]byte, error) {
	if err := validateNativeObjectID("id", item.ID); err != nil {
		return nil, err
	}
	if err := validateNativeObjectID("vaultId", item.VaultID); err != nil {
		return nil, err
	}
	item.Category = nativeItemCategory(item.Category)
	response, err := json.Marshal(item)
	if err != nil {
		return nil, fmt.Errorf("serialize item: %w", err)
	}
	return response, nil
}

func nativeItemCategory(category string) string {
	if category == "API_CREDENTIAL" {
		return "ApiCredentials"
	}
	return category
}

func nativeB5ItemCategory(category string) string {
	if category == "ApiCredentials" {
		return "API_CREDENTIAL"
	}
	return category
}

func nativeItemBatchPath(vaultID string) string {
	// ponytail: symbol-derived route; keep isolated until live API proof confirms or corrects it.
	return "/api/v4/vault/" + url.PathEscape(vaultID) + "/item/itemsbatch"
}

type nativeItemWriteSource struct {
	ID        string          `json:"id"`
	Title     string          `json:"title"`
	Category  string          `json:"category"`
	VaultID   string          `json:"vaultId"`
	Fields    json.RawMessage `json:"fields"`
	Sections  json.RawMessage `json:"sections"`
	Notes     string          `json:"notes"`
	Tags      []string        `json:"tags"`
	Websites  json.RawMessage `json:"websites"`
	Version   uint32          `json:"version"`
	Files     json.RawMessage `json:"files"`
	Document  json.RawMessage `json:"document"`
	CreatedAt json.RawMessage `json:"createdAt"`
	UpdatedAt json.RawMessage `json:"updatedAt"`
	State     string          `json:"state"`
}

type nativeItemWriteOverview struct {
	ID        string          `json:"id,omitempty"`
	Title     string          `json:"title,omitempty"`
	Category  string          `json:"category,omitempty"`
	VaultID   string          `json:"vaultId,omitempty"`
	Websites  json.RawMessage `json:"websites,omitempty"`
	Tags      []string        `json:"tags,omitempty"`
	CreatedAt json.RawMessage `json:"createdAt,omitempty"`
	UpdatedAt json.RawMessage `json:"updatedAt,omitempty"`
	State     string          `json:"state,omitempty"`
}

type nativeItemWriteDetails struct {
	ID       string          `json:"id,omitempty"`
	Title    string          `json:"title,omitempty"`
	Category string          `json:"category,omitempty"`
	VaultID  string          `json:"vaultId,omitempty"`
	Fields   json.RawMessage `json:"fields,omitempty"`
	Sections json.RawMessage `json:"sections,omitempty"`
	Notes    string          `json:"notes,omitempty"`
	Tags     []string        `json:"tags,omitempty"`
	Websites json.RawMessage `json:"websites,omitempty"`
	Version  uint32          `json:"version,omitempty"`
	Files    json.RawMessage `json:"files,omitempty"`
	Document json.RawMessage `json:"document,omitempty"`
}

func nativeEncryptItemPayload(item nativeItemObject, vaultKeySN int, vaultKey nativeSymmetricKey) (nativeEncryptedItemData, error) {
	overviewIV := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, overviewIV); err != nil {
		return nativeEncryptedItemData{}, fmt.Errorf("generate item overview iv: %w", err)
	}
	detailsIV := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, detailsIV); err != nil {
		return nativeEncryptedItemData{}, fmt.Errorf("generate item details iv: %w", err)
	}
	return nativeEncryptItemPayloadWithIVs(item, vaultKeySN, vaultKey, overviewIV, detailsIV)
}

func (c *nativeClient) encryptItemForWrite(ctx context.Context, item nativeItemObject) (nativeEncryptedItemData, error) {
	if err := validateNativeObjectID("vaultId", item.VaultID); err != nil {
		return nativeEncryptedItemData{}, err
	}
	vaultKeys, err := c.unlockedVaultKeys(ctx, item.VaultID)
	if err != nil {
		return nativeEncryptedItemData{}, err
	}
	vaultKeySN, vaultKey, err := nativeLatestVaultKey(vaultKeys)
	if err != nil {
		return nativeEncryptedItemData{}, err
	}
	return nativeEncryptItemPayload(item, vaultKeySN, vaultKey)
}

func nativeEncryptItemPayloadWithIVs(item nativeItemObject, vaultKeySN int, vaultKey nativeSymmetricKey, overviewIV, detailsIV []byte) (nativeEncryptedItemData, error) {
	var source nativeItemWriteSource
	if err := json.Unmarshal(item.Raw, &source); err != nil {
		return nativeEncryptedItemData{}, fmt.Errorf("decode item write payload: %w", err)
	}

	source.ID = firstNonEmpty(source.ID, item.ID)
	source.VaultID = firstNonEmpty(source.VaultID, item.VaultID)
	source.Category = nativeB5ItemCategory(source.Category)
	source.State = firstNonEmpty(source.State, "active")

	overviewPlaintext, err := json.Marshal(nativeItemWriteOverview{
		ID:        source.ID,
		Title:     source.Title,
		Category:  source.Category,
		VaultID:   source.VaultID,
		Websites:  nonNullRaw(source.Websites),
		Tags:      source.Tags,
		CreatedAt: nonNullRaw(source.CreatedAt),
		UpdatedAt: nonNullRaw(source.UpdatedAt),
		State:     source.State,
	})
	if err != nil {
		return nativeEncryptedItemData{}, fmt.Errorf("serialize item overview plaintext: %w", err)
	}
	detailsPlaintext, err := json.Marshal(nativeItemWriteDetails{
		ID:       source.ID,
		Title:    source.Title,
		Category: source.Category,
		VaultID:  source.VaultID,
		Fields:   nonNullRaw(source.Fields),
		Sections: nonNullRaw(source.Sections),
		Notes:    source.Notes,
		Tags:     source.Tags,
		Websites: nonNullRaw(source.Websites),
		Version:  source.Version,
		Files:    nonNullRaw(source.Files),
		Document: nonNullRaw(source.Document),
	})
	if err != nil {
		return nativeEncryptedItemData{}, fmt.Errorf("serialize item details plaintext: %w", err)
	}

	encOverview, err := vaultKey.encryptJWKWithIV(overviewPlaintext, overviewIV)
	if err != nil {
		return nativeEncryptedItemData{}, err
	}
	encDetails, err := vaultKey.encryptJWKWithIV(detailsPlaintext, detailsIV)
	if err != nil {
		return nativeEncryptedItemData{}, err
	}
	return nativeEncryptedItemData{
		UUID:        source.ID,
		Type:        source.Category,
		ItemVersion: source.Version,
		EncOverview: encOverview,
		EncDetails:  encDetails,
		EncryptedBy: vaultKey.ID,
		VaultKeySN:  vaultKeySN,
		CreatedAt:   nonNullRaw(source.CreatedAt),
		UpdatedAt:   nonNullRaw(source.UpdatedAt),
	}, nil
}

func nonNullRaw(value json.RawMessage) json.RawMessage {
	if len(value) == 0 || string(value) == "null" {
		return nil
	}
	return value
}

func nativeItemFieldValue(item nativeItemResponse, id string) (string, bool) {
	value, err := nativeSecretValueFromItem(item, nativeSecretReference{Field: id})
	return value, err == nil
}

func nativeItemOverviewMatches(overview nativeItemOverview, title, category, tag string) bool {
	if overview.Title != title || overview.Category != category {
		return false
	}
	for _, itemTag := range overview.Tags {
		if itemTag == tag {
			return true
		}
	}
	return false
}

func nativePatchedItem(response nativePatchVaultItemsResponse, vaultID, itemID string, vaultKeys map[int]nativeSymmetricKey) (nativeItemResponse, error) {
	if len(response.FailedItems) > 0 {
		for _, failure := range response.FailedItems {
			if nativePatchFailureUUID(failure) == itemID {
				return nativeItemResponse{}, nativePatchItemFailureError(failure)
			}
		}
		return nativeItemResponse{}, nativePatchItemFailureError(response.FailedItems[0])
	}
	for _, updated := range response.UpdatedItems {
		if updated.UUID == itemID {
			return updated.decryptItem(vaultID, vaultKeys)
		}
	}
	return nativeItemResponse{}, nativeError("Internal", "updated item was not found in the server response")
}

func nativePatchItemFailureError(failure nativePatchItemFailure) error {
	if failure.Error != nil {
		return nativeError(nativePatchFailureName(failure.Error.Type), firstNonEmpty(failure.Error.Message, failure.Message, failure.Reason))
	}
	return nativeError(nativePatchFailureName(failure.Reason), firstNonEmpty(failure.Message, failure.Reason))
}

func nativePatchFailureName(reason string) string {
	switch reason {
	case "itemValidationError":
		return "InvalidUserInput"
	case "itemStatusPermissionError":
		return "PermissionDenied"
	case "itemNotFound", "itemStatusFileNotFound":
		return "NotFound"
	case "itemStatusIncorrectItemVersion":
		return "Conflict"
	case "itemStatusTooBig":
		return "InvalidUserInput"
	default:
		return "ServerError"
	}
}

func (c *nativeClient) listItems(ctx context.Context, request nativeItemsListParams) ([]byte, error) {
	if err := c.ensureSession(ctx); err != nil {
		return nil, err
	}
	var raw json.RawMessage
	if err := c.doNativeJSON(ctx, http.MethodGet, nativeItemOverviewsPath(request.VaultID), nil, &raw); err != nil {
		return nil, err
	}
	items, err := c.decodeItemOverviews(ctx, request.VaultID, raw)
	if err != nil {
		return nil, err
	}
	return nativeEncodeItemOverviews(items, request.Filters)
}

func nativeItemOverviewsPath(vaultID string) string {
	return "/api/v1/vault/" + url.PathEscape(vaultID) + "/items/overviews"
}

func nativeItemPath(vaultID, itemID string) string {
	return "/api/v1/vault/" + url.PathEscape(vaultID) + "/item/" + url.PathEscape(itemID)
}

func (c *nativeClient) decodeItemOverviews(ctx context.Context, vaultID string, raw json.RawMessage) ([]nativeItemOverview, error) {
	encryptedItems, err := nativeEncryptedItems(raw)
	if err != nil {
		return nil, err
	}
	vaultKeys, err := c.unlockedVaultKeys(ctx, vaultID)
	if err != nil {
		return nil, err
	}
	items := make([]nativeItemOverview, 0, len(encryptedItems))
	for _, encrypted := range encryptedItems {
		overview, err := encrypted.decryptOverview(vaultID, vaultKeys)
		if err != nil {
			return nil, err
		}
		items = append(items, overview)
	}
	return items, nil
}

func (c *nativeClient) decodeItem(ctx context.Context, vaultID string, raw json.RawMessage) (nativeItemResponse, error) {
	var wrapped nativeEncryptedItemDetailsResponse
	if err := json.Unmarshal(raw, &wrapped); err != nil || wrapped.Item.UUID == "" {
		var encrypted nativeEncryptedItemData
		if err := json.Unmarshal(raw, &encrypted); err != nil {
			return nativeItemResponse{}, err
		}
		wrapped.Item = encrypted
	}
	vaultKeys, err := c.unlockedVaultKeys(ctx, vaultID)
	if err != nil {
		return nativeItemResponse{}, err
	}
	return wrapped.Item.decryptItem(vaultID, vaultKeys)
}

func nativeEncryptedItems(raw json.RawMessage) ([]nativeEncryptedItemData, error) {
	var items []nativeEncryptedItemData
	if err := json.Unmarshal(raw, &items); err == nil {
		return items, nil
	}
	var wrapped nativeEncryptedItemOverviewsResponse
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, err
	}
	return wrapped.Items, nil
}

func (i nativeEncryptedItemData) decryptOverview(vaultID string, vaultKeys map[int]nativeSymmetricKey) (nativeItemOverview, error) {
	key, err := nativeVaultKeyForItem(i, vaultKeys)
	if err != nil {
		return nativeItemOverview{}, err
	}
	plaintext, err := key.decryptJWK(i.EncOverview)
	if err != nil {
		return nativeItemOverview{}, err
	}
	var overview nativeItemOverview
	if err := json.Unmarshal(plaintext, &overview); err != nil {
		return nativeItemOverview{}, fmt.Errorf("decode item overview: %w", err)
	}
	overview.ID = firstNonEmpty(overview.ID, i.UUID)
	overview.VaultID = firstNonEmpty(overview.VaultID, vaultID)
	overview.Category = firstNonEmpty(overview.Category, i.Type)
	overview.State = firstNonEmpty(overview.State, nativeItemStateFromTrashed(i.Trashed))
	overview.CreatedAt = firstRaw(overview.CreatedAt, i.CreatedAt)
	overview.UpdatedAt = firstRaw(overview.UpdatedAt, i.UpdatedAt)
	return overview, nil
}

func (i nativeEncryptedItemData) decryptItem(vaultID string, vaultKeys map[int]nativeSymmetricKey) (nativeItemResponse, error) {
	overview, err := i.decryptOverview(vaultID, vaultKeys)
	if err != nil {
		return nativeItemResponse{}, err
	}
	key, err := nativeVaultKeyForItem(i, vaultKeys)
	if err != nil {
		return nativeItemResponse{}, err
	}
	plaintext, err := key.decryptJWK(i.EncDetails)
	if err != nil {
		return nativeItemResponse{}, err
	}
	var details nativeItemResponse
	if err := json.Unmarshal(plaintext, &details); err != nil {
		return nativeItemResponse{}, fmt.Errorf("decode item details: %w", err)
	}
	details.ID = firstNonEmpty(details.ID, overview.ID)
	details.Title = firstNonEmpty(details.Title, overview.Title)
	details.Category = nativeItemCategory(firstNonEmpty(details.Category, overview.Category))
	details.VaultID = firstNonEmpty(details.VaultID, overview.VaultID)
	details.Tags = firstStrings(details.Tags, overview.Tags)
	details.Websites = firstRaw(details.Websites, overview.Websites)
	details.CreatedAt = firstRaw(details.CreatedAt, overview.CreatedAt)
	details.UpdatedAt = firstRaw(details.UpdatedAt, overview.UpdatedAt)
	details.Version = firstUint32(details.Version, i.ItemVersion)
	return details, nil
}

func nativeVaultKeyForItem(item nativeEncryptedItemData, vaultKeys map[int]nativeSymmetricKey) (nativeSymmetricKey, error) {
	if item.VaultKeySN != 0 {
		if key, ok := vaultKeys[item.VaultKeySN]; ok {
			return key, nil
		}
		return nativeSymmetricKey{}, fmt.Errorf("vault key serial %d was not found", item.VaultKeySN)
	}
	for _, key := range vaultKeys {
		if key.ID == item.EncryptedBy || key.ID == item.EncOverview.KeyID || key.ID == item.EncDetails.KeyID {
			return key, nil
		}
	}
	return nativeSymmetricKey{}, fmt.Errorf("vault key for encrypted item %q was not found", item.UUID)
}

func nativeItemStateFromTrashed(trashed string) string {
	if strings.TrimSpace(trashed) == "" {
		return "active"
	}
	return "archived"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func firstRaw(values ...json.RawMessage) json.RawMessage {
	for _, value := range values {
		if len(value) != 0 {
			return value
		}
	}
	return nil
}

func firstStrings(values ...[]string) []string {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}

func firstUint32(values ...uint32) uint32 {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}

func (c *nativeClient) getItem(ctx context.Context, request nativeVaultItemParams) ([]byte, error) {
	item, err := c.getItemResponse(ctx, request)
	if err != nil {
		return nil, err
	}
	return nativeEncodeItem(item)
}

func (c *nativeClient) getItemResponse(ctx context.Context, request nativeVaultItemParams) (nativeItemResponse, error) {
	if err := c.ensureSession(ctx); err != nil {
		return nativeItemResponse{}, err
	}
	var raw json.RawMessage
	if err := c.doNativeJSON(ctx, http.MethodGet, nativeItemPath(request.VaultID, request.ItemID), nil, &raw); err != nil {
		return nativeItemResponse{}, err
	}
	return c.decodeItem(ctx, request.VaultID, raw)
}

func (c *nativeClient) getItems(ctx context.Context, request nativeVaultItemsParams) ([]byte, error) {
	if err := c.ensureSession(ctx); err != nil {
		return nil, err
	}
	response := nativeItemsGetAllResponse{
		IndividualResponses: make([]nativeItemGetAllResponse, 0, len(request.ItemIDs)),
	}
	for _, itemID := range request.ItemIDs {
		item, err := c.getItemResponse(ctx, nativeVaultItemParams{VaultID: request.VaultID, ItemID: itemID})
		switch {
		case err == nil:
			response.IndividualResponses = append(response.IndividualResponses, nativeItemGetAllResponse{Content: &item})
		case nativeErrorName(err) == "NotFound":
			response.IndividualResponses = append(response.IndividualResponses, nativeItemGetAllResponse{Error: &nativeItemsGetAllErr{Type: "itemNotFound"}})
		default:
			response.IndividualResponses = append(response.IndividualResponses, nativeItemGetAllResponse{Error: &nativeItemsGetAllErr{Type: "internal", Message: err.Error()}})
		}
	}
	return json.Marshal(response)
}

func (c *nativeClient) createItem(ctx context.Context, request nativeItemCreateParams) ([]byte, error) {
	item, err := nativeItemForCreate(request.Params, request.Params.VaultID)
	if err != nil {
		return nil, err
	}
	items, vaultKeys, err := c.patchVaultItems(ctx, item.VaultID, []nativeItemObject{item})
	if err != nil {
		return nil, err
	}
	patched, err := nativePatchedItem(items, item.VaultID, item.ID, vaultKeys)
	if err != nil {
		return nil, err
	}
	return nativeEncodeItem(patched)
}

func (c *nativeClient) createItems(ctx context.Context, request nativeItemCreateAllParams) ([]byte, error) {
	items := make([]nativeItemObject, 0, len(request.Params))
	for _, item := range request.Params {
		created, err := nativeItemForCreate(item, request.VaultID)
		if err != nil {
			return nil, err
		}
		items = append(items, created)
	}
	response, vaultKeys, err := c.patchVaultItems(ctx, request.VaultID, items)
	if err != nil {
		return nil, err
	}
	out := nativeItemsUpdateAllResponseFromPatch(request.VaultID, items, response, vaultKeys)
	return json.Marshal(out)
}

func nativeItemsUpdateAllResponseFromPatch(vaultID string, requestedItems []nativeItemObject, response nativePatchVaultItemsResponse, vaultKeys map[int]nativeSymmetricKey) nativeItemsUpdateAllResponse {
	out := nativeItemsUpdateAllResponse{
		IndividualResponses: make([]nativeItemUpdateAllResponse, 0, len(requestedItems)),
	}
	updatedByID := make(map[string]nativeEncryptedItemData, len(response.UpdatedItems))
	for _, item := range response.UpdatedItems {
		updatedByID[item.UUID] = item
	}
	failed := make(map[string]nativePatchItemFailure, len(response.FailedItems))
	for _, failure := range response.FailedItems {
		failed[nativePatchFailureUUID(failure)] = failure
	}
	for _, requested := range requestedItems {
		updatedItem, ok := updatedByID[requested.ID]
		if !ok {
			failure, ok := failed[requested.ID]
			if ok {
				out.IndividualResponses = append(out.IndividualResponses, nativeItemUpdateAllResponse{Error: nativeItemUpdateFailureFromError(nativePatchItemFailureError(failure))})
				continue
			}
			out.IndividualResponses = append(out.IndividualResponses, nativeItemUpdateAllResponse{Error: &nativeItemUpdateFailureError{Type: "internal", Message: "updated item was not found in the server response"}})
			continue
		}
		item, err := updatedItem.decryptItem(vaultID, vaultKeys)
		if err != nil {
			out.IndividualResponses = append(out.IndividualResponses, nativeItemUpdateAllResponse{Error: &nativeItemUpdateFailureError{Type: "internal", Message: err.Error()}})
			continue
		}
		out.IndividualResponses = append(out.IndividualResponses, nativeItemUpdateAllResponse{Content: &item})
	}
	return out
}

func nativePatchFailureUUID(failure nativePatchItemFailure) string {
	return firstNonEmpty(failure.UUID, failure.ItemUUID)
}

func (c *nativeClient) putItem(ctx context.Context, request nativeItemPutParams) ([]byte, error) {
	items, vaultKeys, err := c.patchVaultItems(ctx, request.Item.VaultID, []nativeItemObject{request.Item})
	if err != nil {
		return nil, err
	}
	patched, err := nativePatchedItem(items, request.Item.VaultID, request.Item.ID, vaultKeys)
	if err != nil {
		return nil, err
	}
	return nativeEncodeItem(patched)
}

func (c *nativeClient) patchVaultItems(ctx context.Context, vaultID string, items []nativeItemObject) (nativePatchVaultItemsResponse, map[int]nativeSymmetricKey, error) {
	if err := c.ensureSession(ctx); err != nil {
		return nativePatchVaultItemsResponse{}, nil, err
	}
	contentVersion, err := c.vaultContentVersion(ctx, vaultID)
	if err != nil {
		return nativePatchVaultItemsResponse{}, nil, err
	}
	vaultKeys, err := c.unlockedVaultKeys(ctx, vaultID)
	if err != nil {
		return nativePatchVaultItemsResponse{}, nil, err
	}
	vaultKeySN, vaultKey, err := nativeLatestVaultKey(vaultKeys)
	if err != nil {
		return nativePatchVaultItemsResponse{}, nil, err
	}
	encrypted := make([]nativeEncryptedItemData, 0, len(items))
	for _, item := range items {
		data, err := nativeEncryptItemPayload(item, vaultKeySN, vaultKey)
		if err != nil {
			return nativePatchVaultItemsResponse{}, nil, err
		}
		encrypted = append(encrypted, data)
	}
	var response nativePatchVaultItemsResponse
	err = c.doNativeJSON(ctx, http.MethodPatch, nativeItemBatchPath(vaultID), nativePatchVaultItemsRequest{
		ContentVersion: contentVersion,
		Items:          encrypted,
	}, &response)
	return response, vaultKeys, err
}

func nativeItemForCreate(item nativeItemObject, vaultID string) (nativeItemObject, error) {
	if item.ID == "" {
		id, err := randomNativeObjectID()
		if err != nil {
			return nativeItemObject{}, err
		}
		item.ID = id
	}
	if err := validateNativeObjectID("id", item.ID); err != nil {
		return nativeItemObject{}, err
	}
	item.VaultID = firstNonEmpty(item.VaultID, vaultID)
	if err := validateNativeObjectID("vaultId", item.VaultID); err != nil {
		return nativeItemObject{}, err
	}
	return nativeItemWithRawFields(item, map[string]interface{}{
		"id":      item.ID,
		"vaultId": item.VaultID,
		"version": firstUint32(nativeItemVersion(item.Raw), 1),
	})
}

func nativeItemWithRawFields(item nativeItemObject, fields map[string]interface{}) (nativeItemObject, error) {
	var raw map[string]interface{}
	if len(item.Raw) > 0 {
		if err := json.Unmarshal(item.Raw, &raw); err != nil {
			return nativeItemObject{}, err
		}
	} else {
		raw = map[string]interface{}{}
	}
	for key, value := range fields {
		raw[key] = value
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nativeItemObject{}, err
	}
	item.Raw = encoded
	return item, nil
}

func nativeItemVersion(raw json.RawMessage) uint32 {
	var item struct {
		Version uint32 `json:"version"`
	}
	if json.Unmarshal(raw, &item) != nil {
		return 0
	}
	return item.Version
}

func randomNativeObjectID() (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	id, err := RandomString(alphabet, 26)
	if err != nil {
		return "", fmt.Errorf("generate item id: %w", err)
	}
	return id, nil
}

func (c *nativeClient) deleteItem(ctx context.Context, request nativeVaultItemParams) ([]byte, error) {
	if err := c.ensureSession(ctx); err != nil {
		return nil, err
	}
	if err := c.doNativeJSON(ctx, http.MethodDelete, nativeItemPath(request.VaultID, request.ItemID), nil, nil); err != nil {
		return nil, err
	}
	return []byte("null"), nil
}

func (c *nativeClient) deleteItems(ctx context.Context, request nativeVaultItemsParams) ([]byte, error) {
	if err := c.ensureSession(ctx); err != nil {
		return nil, err
	}
	response := nativeItemsDeleteAllResponse{
		IndividualResponses: make(map[string]nativeItemDeleteAllResponse, len(request.ItemIDs)),
	}
	for _, itemID := range request.ItemIDs {
		_, err := c.deleteItem(ctx, nativeVaultItemParams{VaultID: request.VaultID, ItemID: itemID})
		if err == nil {
			response.IndividualResponses[itemID] = nativeItemDeleteAllResponse{Content: &struct{}{}}
			continue
		}
		response.IndividualResponses[itemID] = nativeItemDeleteAllResponse{Error: nativeItemUpdateFailureFromError(err)}
	}
	return json.Marshal(response)
}

func (c *nativeClient) archiveItem(nativeVaultItemParams) ([]byte, error) {
	return nil, nativeMethodNotImplemented("ItemsArchive")
}

func nativeMethodNotImplemented(method string) error {
	return nativeMethodNotImplementedError{method: method}
}

func isNativeMethodNotImplemented(err error) bool {
	var target nativeMethodNotImplementedError
	return errors.As(err, &target)
}

type nativeMethodNotImplementedError struct {
	method string
}

func (e nativeMethodNotImplementedError) Error() string {
	return nativeError("NativeMethodNotImplemented", fmt.Sprintf("native core cannot run %q until its service-account route is implemented", e.method)).Error()
}

func nativeItemUpdateFailureFromError(err error) *nativeItemUpdateFailureError {
	if err == nil {
		return nil
	}
	switch nativeErrorName(err) {
	case "InvalidUserInput":
		return &nativeItemUpdateFailureError{Type: "itemValidationError", Message: err.Error()}
	case "PermissionDenied":
		return &nativeItemUpdateFailureError{Type: "itemStatusPermissionError"}
	case "NotFound":
		return &nativeItemUpdateFailureError{Type: "itemNotFound"}
	case "Conflict":
		return &nativeItemUpdateFailureError{Type: "itemStatusIncorrectItemVersion"}
	default:
		return &nativeItemUpdateFailureError{Type: "internal", Message: err.Error()}
	}
}

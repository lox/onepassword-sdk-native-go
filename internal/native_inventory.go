package internal

import (
	"context"
	"encoding/json"
	"net/http"
)

func (c *NativeCore) invokeNativeInventory(ctx context.Context, invocation InvokeConfig) ([]byte, bool, error) {
	method := invocation.Invocation.Parameters.MethodName
	params := invocation.Invocation.Parameters.SerializedParams

	switch method {
	case "VaultsList":
		request, err := nativeVaultsListRequest(params)
		if err != nil {
			return nil, true, nativeError("InvalidUserInput", err.Error())
		}
		client, err := c.nativeInventoryClient(invocation)
		if err != nil {
			return nil, true, err
		}
		response, err := client.listVaults(ctx, request)
		return response, true, err
	case "VaultsGetOverview":
		request, err := nativeVaultRequest(params)
		if err != nil {
			return nil, true, nativeError("InvalidUserInput", err.Error())
		}
		client, err := c.nativeInventoryClient(invocation)
		if err != nil {
			return nil, true, err
		}
		response, err := client.getVaultOverview(ctx, request)
		return response, true, err
	case "VaultsGet":
		request, err := nativeVaultGetRequest(params)
		if err != nil {
			return nil, true, nativeError("InvalidUserInput", err.Error())
		}
		client, err := c.nativeInventoryClient(invocation)
		if err != nil {
			return nil, true, err
		}
		response, err := client.getVault(ctx, request)
		return response, true, err
	case "GroupsGet":
		request, err := nativeGroupGetRequest(params)
		if err != nil {
			return nil, true, nativeError("InvalidUserInput", err.Error())
		}
		client, err := c.nativeInventoryClient(invocation)
		if err != nil {
			return nil, true, err
		}
		response, err := client.getGroup(request)
		return response, true, err
	default:
		return nil, false, nil
	}
}

func (c *NativeCore) nativeInventoryClient(invocation InvokeConfig) (*nativeClient, error) {
	if invocation.Invocation.ClientID == nil {
		return nil, nativeError("Internal", "native inventory method requires a client id")
	}
	return c.client(*invocation.Invocation.ClientID)
}

type nativeVaultsListParams struct {
	Params json.RawMessage `json:"params"`
}

type nativeVaultParams struct {
	VaultID string `json:"vault_id"`
}

type nativeVaultGetParams struct {
	VaultID     string          `json:"vault_id"`
	VaultParams json.RawMessage `json:"vault_params"`
}

type nativeGroupGetParams struct {
	GroupID     string          `json:"group_id"`
	GroupParams json.RawMessage `json:"group_params"`
}

func nativeVaultsListRequest(params map[string]interface{}) (nativeVaultsListParams, error) {
	var request nativeVaultsListParams
	if err := decodeNativeParams(params, &request); err != nil {
		return nativeVaultsListParams{}, err
	}
	return request, nil
}

func emptyJSON(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	var value interface{}
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	if value == nil {
		return true
	}
	if object, ok := value.(map[string]interface{}); ok && len(object) == 0 {
		return true
	}
	return false
}

func nativeVaultRequest(params map[string]interface{}) (nativeVaultParams, error) {
	if _, ok := params["vault_id"]; !ok {
		return nativeVaultParams{}, missingParameterError("vault_id")
	}
	var request nativeVaultParams
	if err := decodeNativeParams(params, &request); err != nil {
		return nativeVaultParams{}, err
	}
	if err := validateNativeObjectID("vault_id", request.VaultID); err != nil {
		return nativeVaultParams{}, err
	}
	return request, nil
}

func nativeVaultGetRequest(params map[string]interface{}) (nativeVaultGetParams, error) {
	if _, ok := params["vault_id"]; !ok {
		return nativeVaultGetParams{}, missingParameterError("vault_id")
	}
	var request nativeVaultGetParams
	if err := decodeNativeParams(params, &request); err != nil {
		return nativeVaultGetParams{}, err
	}
	if err := validateNativeObjectID("vault_id", request.VaultID); err != nil {
		return nativeVaultGetParams{}, err
	}
	return request, nil
}

func nativeGroupGetRequest(params map[string]interface{}) (nativeGroupGetParams, error) {
	if _, ok := params["group_id"]; !ok {
		return nativeGroupGetParams{}, missingParameterError("group_id")
	}
	var request nativeGroupGetParams
	if err := decodeNativeParams(params, &request); err != nil {
		return nativeGroupGetParams{}, err
	}
	if err := validateNativeObjectID("group_id", request.GroupID); err != nil {
		return nativeGroupGetParams{}, err
	}
	return request, nil
}

func missingParameterError(name string) error {
	return nativeParameterError{message: `missing parameter "` + name + `"`}
}

type nativeParameterError struct {
	message string
}

func (e nativeParameterError) Error() string {
	return e.message
}

func (c *nativeClient) listVaults(ctx context.Context, request nativeVaultsListParams) ([]byte, error) {
	if !emptyJSON(request.Params) {
		return nil, nativeMethodNotImplemented("VaultsList")
	}
	if err := c.ensureSession(ctx); err != nil {
		return nil, err
	}
	var vaults []json.RawMessage
	if err := c.doNativeJSON(ctx, http.MethodGet, "/api/v1/vaults", nil, &vaults); err != nil {
		return nil, err
	}
	return json.Marshal(vaults)
}

func (c *nativeClient) getVaultOverview(ctx context.Context, request nativeVaultParams) ([]byte, error) {
	response, err := c.listVaults(ctx, nativeVaultsListParams{})
	if err != nil {
		if isNativeMethodNotImplemented(err) {
			return nil, nativeMethodNotImplemented("VaultsGetOverview")
		}
		return nil, err
	}
	var vaults []json.RawMessage
	if err := json.Unmarshal(response, &vaults); err != nil {
		return nil, err
	}
	for _, vault := range vaults {
		var overview struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(vault, &overview); err != nil {
			return nil, err
		}
		if overview.ID == request.VaultID {
			return json.Marshal(vault)
		}
	}
	return nil, nativeError("NotFound", "resource not found")
}

func (c *nativeClient) vaultContentVersion(ctx context.Context, vaultID string) (uint64, error) {
	response, err := c.getVaultOverview(ctx, nativeVaultParams{VaultID: vaultID})
	if err != nil {
		return 0, err
	}
	var vault struct {
		ContentVersion uint64 `json:"contentVersion"`
	}
	if err := json.Unmarshal(response, &vault); err != nil {
		return 0, err
	}
	if vault.ContentVersion == 0 {
		return 0, nativeError("Internal", "vault metadata is missing contentVersion")
	}
	return vault.ContentVersion, nil
}

func (c *nativeClient) getVault(ctx context.Context, request nativeVaultGetParams) ([]byte, error) {
	if !emptyJSON(request.VaultParams) {
		return nil, nativeMethodNotImplemented("VaultsGet")
	}
	response, err := c.getVaultOverview(ctx, nativeVaultParams{VaultID: request.VaultID})
	if err != nil {
		if isNativeMethodNotImplemented(err) {
			return nil, nativeMethodNotImplemented("VaultsGet")
		}
		return nil, err
	}
	return response, nil
}

func (c *nativeClient) getGroup(nativeGroupGetParams) ([]byte, error) {
	return nil, nativeMethodNotImplemented("GroupsGet")
}

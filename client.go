package onepassword

import (
	"github.com/lox/onepassword-sdk-native-go/internal"
)

// Client represents an instance of the Native 1Password Go SDK client.
type Client struct {
	config     internal.ClientConfig
	SecretsAPI SecretsAPI
	ItemsAPI   ItemsAPI
	VaultsAPI  VaultsAPI
	GroupsAPI  GroupsAPI
}

func initAPIs(client *Client, inner *internal.InnerClient) {
	client.SecretsAPI = NewSecretsSource(inner)
	client.ItemsAPI = NewItemsSource(inner)
	client.VaultsAPI = NewVaultsSource(inner)
	client.GroupsAPI = NewGroupsSource(inner)
}

func (c *Client) Secrets() SecretsAPI {
	return c.SecretsAPI
}
func (c *Client) Items() ItemsAPI {
	return c.ItemsAPI
}
func (c *Client) Vaults() VaultsAPI {
	return c.VaultsAPI
}
func (c *Client) Groups() GroupsAPI {
	return c.GroupsAPI
}

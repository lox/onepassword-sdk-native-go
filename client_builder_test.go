package onepassword

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/lox/onepassword-sdk-native-go/internal"
)

type refreshCore struct {
	invokes  int
	released []uint64
}

func (c *refreshCore) InitClient(context.Context, []byte) ([]byte, error) {
	return json.Marshal(uint64(2))
}

func (c *refreshCore) Invoke(context.Context, []byte) ([]byte, error) {
	c.invokes++
	if c.invokes == 1 {
		return nil, internalError("DesktopSessionExpired", "expired")
	}
	return []byte(`"ok"`), nil
}

func (c *refreshCore) ReleaseClient(clientID []byte) {
	var id uint64
	if json.Unmarshal(clientID, &id) == nil {
		c.released = append(c.released, id)
	}
}

func TestClientInvokeReleasesExpiredDesktopClient(t *testing.T) {
	core := &refreshCore{}
	inner := &internal.InnerClient{
		ID:   1,
		Core: internal.CoreWrapper{InnerCore: core},
	}

	got, err := clientInvoke(context.Background(), inner, "SecretsResolve", map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || *got != `"ok"` {
		t.Fatalf("got %v, want ok response", got)
	}
	if inner.ID != 2 {
		t.Fatalf("got refreshed client id %d, want 2", inner.ID)
	}
	if len(core.released) != 1 || core.released[0] != 1 {
		t.Fatalf("released clients = %v, want [1]", core.released)
	}

	releaseInnerClient(inner)
	if len(core.released) != 2 || core.released[1] != 2 {
		t.Fatalf("released clients = %v, want refreshed client release", core.released)
	}
}

func internalError(name, message string) error {
	payload, _ := json.Marshal(struct {
		Name    string `json:"name"`
		Message string `json:"message"`
	}{Name: name, Message: message})
	return errors.New(string(payload))
}

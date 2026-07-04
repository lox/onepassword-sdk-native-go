package integration_tests

import (
	"context"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/lox/onepassword-sdk-native-go"
	"github.com/lox/onepassword-sdk-native-go/internal"
)

// These tests were designed for CI/CD. If you want to run them locally you must make sure the following dependencies are in place:
// A valid (test) Service Account Token is set in the environment - export OP_SERVICE_ACCOUNT_TOKEN = ...
// Secret references and expected values are matching existing secrets in the test account.

func TestSecretRetrievalFromTestAccount(t *testing.T) {
	token := serviceAccountToken(t)
	client, err := onepassword.NewClient(context.Background(),
		onepassword.WithServiceAccountToken(token),
		onepassword.WithIntegrationInfo("Integration_Test_Go_SDK", onepassword.DefaultIntegrationVersion),
	)
	requireNoError(t, err)

	secret, err := client.Secrets().Resolve(context.Background(), "op://gowwbvgow7kxocrfmfvtwni6vi/6ydrn7ne6mwnqc2prsbqx4i4aq/password")
	requireNoError(t, err)

	if secret != "test_password_42" {
		t.Fatalf("secret = %q, want %q", secret, "test_password_42")
	}
}

func TestRetrivalWithMultipleClients(t *testing.T) {
	TestSecretRetrievalFromTestAccount(t)
	TestSecretRetrievalFromTestAccount(t)
	TestSecretRetrievalFromTestAccount(t)

	// keep creating clients to check what happens
	token := serviceAccountToken(t)
	core := internal.GetNativeCore()
	config := internal.NewDefaultConfig()
	config.SAToken = token
	config.IntegrationName = "name"
	config.IntegrationVersion = "version"

	ctx := context.Background()
	value1, err1 := core.InitClient(ctx, config)
	requireNoError(t, err1)
	value2, err2 := core.InitClient(ctx, config)
	requireNoError(t, err2)
	value3, err3 := core.InitClient(ctx, config)
	requireNoError(t, err3)

	if *value1 != 3 || *value2 != 4 || *value3 != 5 {
		t.Fatalf("client IDs = %d, %d, %d; want 3, 4, 5", *value1, *value2, *value3)
	}
}

func TestInvalidInvoke(t *testing.T) {
	token := serviceAccountToken(t)

	core := internal.GetNativeCore()

	config := internal.NewDefaultConfig()
	config.SAToken = token
	config.IntegrationName = "name"
	config.IntegrationVersion = "version"

	_, err := core.InitClient(context.Background(), config)
	requireNoError(t, err)

	validClientID := uint64(0)
	validMethodName := "SecretsResolve"
	validParams := map[string]interface{}{"secret_reference": "op://gowwbvgow7kxocrfmfvtwni6vi/6ydrn7ne6mwnqc2prsbqx4i4aq/password"}
	invalidClientID := uint64(1)
	invalidMethodName := "InvalidName"
	invalidParams := map[string]interface{}{"secret_reference": ""}

	// invalid client id
	invocation1 := internal.InvokeConfig{
		Invocation: internal.Invocation{
			ClientID: &invalidClientID,
			Parameters: internal.Parameters{
				MethodName:       validMethodName,
				SerializedParams: validParams,
			},
		},
	}
	_, err1 := core.Invoke(context.Background(), invocation1)
	requireErrorEqual(t, err1, "{\"name\":\"Internal\",\"message\":\"invalid client id\"}")

	// invalid method name
	invocation2 := internal.InvokeConfig{
		Invocation: internal.Invocation{
			ClientID: &validClientID,
			Parameters: internal.Parameters{
				MethodName:       invalidMethodName,
				SerializedParams: invalidParams,
			},
		}}
	_, err2 := core.Invoke(context.Background(), invocation2)
	if err2 == nil {
		t.Fatal("expected error when sending invocation that doesn't exist")
	}

	// invalid serialized params
	invocation3 := internal.InvokeConfig{
		Invocation: internal.Invocation{
			ClientID: &validClientID,
			Parameters: internal.Parameters{
				MethodName:       validMethodName,
				SerializedParams: invalidParams,
			},
		},
	}
	_, err3 := core.Invoke(context.Background(), invocation3)
	requireErrorEqual(t, err3, "{\"name\":\"InvalidUserInput\",\"message\":\"secret reference is not prefixed with \\\"op://\\\"\"}")
}

func TestClientReleasedSuccessfully(t *testing.T) {
	TestSecretRetrievalFromTestAccount(t)
	runtime.GC()

	core := internal.GetNativeCore()
	clientID := uint64(0)
	invocation := internal.InvokeConfig{
		Invocation: internal.Invocation{
			ClientID: &clientID, // this client id should be invalid because the client has been cleaned up by GC
			Parameters: internal.Parameters{
				MethodName:       "SecretsResolve",
				SerializedParams: map[string]interface{}{"secret_reference": "op://foo/bar/baz"},
			},
		},
	}
	_, err := core.Invoke(context.Background(), invocation)
	requireErrorEqual(t, err, "{\"name\":\"Internal\",\"message\":\"invalid client id\"}")
}

func TestConcurrentCallsFromOneClient(t *testing.T) {
	var wg sync.WaitGroup
	token := serviceAccountToken(t)
	client, err := onepassword.NewClient(context.Background(),
		onepassword.WithServiceAccountToken(token),
		onepassword.WithIntegrationInfo("Integration_Test_Go_SDK", onepassword.DefaultIntegrationVersion),
	)
	requireNoError(t, err)

	concurrentCalls := 10
	wg.Add(concurrentCalls)
	for i := 0; i < concurrentCalls; i++ {
		go func() {
			defer wg.Done()
			secret, err := client.Secrets().Resolve(context.Background(), "op://gowwbvgow7kxocrfmfvtwni6vi/6ydrn7ne6mwnqc2prsbqx4i4aq/password")
			requireNoError(t, err)

			if secret != "test_password_42" {
				t.Errorf("secret = %q, want %q", secret, "test_password_42")
			}
		}()
	}
	wg.Wait()
}

func TestConcurrentCallsFromMultipleClientsOnTheSameToken(t *testing.T) {
	var wg sync.WaitGroup
	token := serviceAccountToken(t)
	concurrentClients := 5
	wg.Add(concurrentClients)
	for i := 0; i < concurrentClients; i++ {
		go func() {
			defer wg.Done()
			client, err := onepassword.NewClient(context.Background(),
				onepassword.WithServiceAccountToken(token),
				onepassword.WithIntegrationInfo("Integration_Test_Go_SDK", onepassword.DefaultIntegrationVersion),
			)
			requireNoError(t, err)

			secret, err := client.Secrets().Resolve(context.Background(), "op://gowwbvgow7kxocrfmfvtwni6vi/6ydrn7ne6mwnqc2prsbqx4i4aq/password")
			requireNoError(t, err)

			if secret != "test_password_42" {
				t.Errorf("secret = %q, want %q", secret, "test_password_42")
			}
		}()
	}
	wg.Wait()
}

func TestExpiredContextCancelsLongRunningOperation(t *testing.T) {
	c := context.Background()
	ctx, cancel := context.WithCancel(c)
	token := serviceAccountToken(t)
	var err error
	out := make(chan error)
	cancel()
	go func() {
		_, err = onepassword.NewClient(ctx,
			onepassword.WithServiceAccountToken(token),
			onepassword.WithIntegrationInfo("Integration_Test_Go_SDK", onepassword.DefaultIntegrationVersion),
		)
		out <- err
	}()

	err = <-out
	requireErrorContains(t, err, `context canceled`)
}

func serviceAccountToken(t *testing.T) string {
	t.Helper()
	token := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
	if token == "" {
		t.Skip("OP_SERVICE_ACCOUNT_TOKEN is required for integration tests")
	}
	return token
}

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func requireErrorEqual(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want %q", want)
	}
	if err.Error() != want {
		t.Fatalf("error = %q, want %q", err.Error(), want)
	}
}

func requireErrorContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want substring %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want substring %q", err.Error(), want)
	}
}

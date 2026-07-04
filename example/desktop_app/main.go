package main

import (
	"context"
	"fmt"
	"os"

	"github.com/lox/onepassword-sdk-native-go"
)

func main() {
	account := os.Getenv("OP_ACCOUNT_NAME")
	if account == "" {
		panic("OP_ACCOUNT_NAME is required")
	}
	ref := os.Getenv("OP_SECRET_REFERENCE")
	if ref == "" {
		panic("OP_SECRET_REFERENCE is required")
	}

	client, err := onepassword.NewClient(
		context.Background(),
		onepassword.WithDesktopAppIntegration(account),
		onepassword.WithIntegrationInfo("Native SDK Desktop Example", "v1.0.0"),
	)
	if err != nil {
		panic(err)
	}

	secret, err := client.Secrets().Resolve(context.Background(), ref)
	if err != nil {
		panic(err)
	}
	fmt.Println(secret)
}

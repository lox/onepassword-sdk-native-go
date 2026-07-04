package main

import (
	"context"
	"fmt"

	onepassword "github.com/lox/onepassword-sdk-native-go"
)

func main() {
	ctx := context.Background()
	if err := onepassword.Secrets.ValidateSecretReference(ctx, "op://vault/item/field"); err != nil {
		panic(err)
	}

	pin, err := onepassword.Secrets.GeneratePassword(ctx, onepassword.NewPasswordRecipeTypeVariantPin(&onepassword.PasswordRecipePinInner{Length: 6}))
	if err != nil {
		panic(err)
	}

	random, err := onepassword.Secrets.GeneratePassword(ctx, onepassword.NewPasswordRecipeTypeVariantRandom(&onepassword.PasswordRecipeRandomInner{
		IncludeDigits:  true,
		IncludeSymbols: true,
		Length:         16,
	}))
	if err != nil {
		panic(err)
	}

	fmt.Printf("valid reference\npin: %s\nrandom: %s\n", pin.Password, random.Password)
}

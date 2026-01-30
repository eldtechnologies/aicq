package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func main() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Public key (base64):  %s\n", base64.StdEncoding.EncodeToString(pub))
	fmt.Printf("Private key (base64): %s\n", base64.StdEncoding.EncodeToString(priv))
}

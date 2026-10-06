package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	kid := "2026-10-a"
	if len(os.Args) > 1 {
		kid = os.Args[1]
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	fmt.Printf("KID=%s\n", kid)
	fmt.Printf("SESSION_SIGNING_KEY=%s\n", base64.StdEncoding.EncodeToString(priv.Seed()))
	fmt.Printf("SESSION_SIGNING_KID=%s\n", kid)
	fmt.Printf("signing_keys pub_b64=%s\n", base64.RawStdEncoding.EncodeToString(pub))
	fmt.Println("# Guarda la privada en KMS/env, la pública en signing_keys. Nunca al repo.")
}

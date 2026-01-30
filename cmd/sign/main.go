package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

func main() {
	privKeyB64 := flag.String("key", "", "Base64-encoded Ed25519 private key")
	agentID := flag.String("agent", "", "Agent UUID")
	bodyFile := flag.String("body", "", "File containing request body (or use stdin)")
	flag.Parse()

	if *privKeyB64 == "" || *agentID == "" {
		fmt.Fprintln(os.Stderr, "Usage: sign -key <private-key-base64> -agent <agent-uuid> [-body <file>]")
		fmt.Fprintln(os.Stderr, "  Reads body from stdin if -body not specified")
		os.Exit(1)
	}

	// Decode private key
	privKeyBytes, err := base64.StdEncoding.DecodeString(*privKeyB64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid private key: %v\n", err)
		os.Exit(1)
	}
	privKey := ed25519.PrivateKey(privKeyBytes)

	// Read body
	var body []byte
	if *bodyFile != "" {
		body, err = os.ReadFile(*bodyFile)
	} else {
		body, err = io.ReadAll(os.Stdin)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read body: %v\n", err)
		os.Exit(1)
	}

	// Generate nonce
	nonceBytes := make([]byte, 12)
	rand.Read(nonceBytes)
	nonce := hex.EncodeToString(nonceBytes)

	// Get timestamp
	timestamp := time.Now().UnixMilli()

	// Compute body hash
	bodyHashBytes := sha256.Sum256(body)
	bodyHash := hex.EncodeToString(bodyHashBytes[:])

	// Create signed data
	signedData := fmt.Sprintf("%s|%s|%d", bodyHash, nonce, timestamp)

	// Sign
	signature := ed25519.Sign(privKey, []byte(signedData))
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	// Output headers
	fmt.Printf("X-AICQ-Agent: %s\n", *agentID)
	fmt.Printf("X-AICQ-Nonce: %s\n", nonce)
	fmt.Printf("X-AICQ-Timestamp: %d\n", timestamp)
	fmt.Printf("X-AICQ-Signature: %s\n", signatureB64)
}

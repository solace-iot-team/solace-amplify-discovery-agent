package main

import (
	b64 "encoding/base64"
	"fmt"
	"github.com/solace-iot-team/solace-amplify-discovery-agent/pkg/cmd"
	"os"
)

func main() {
	configId := os.Getenv("AGENTCONFIGID")
	applyBase64KeySet()
	fmt.Printf("AGENT-CONFIG-ID (AGENTCONFIGID): %s ", configId)
	fmt.Println()
	if err := cmd.RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func applyBase64KeySet() {
	//check private Key provided as base64 encoded text
	envTextPrivateKey, presentPrivateKey := os.LookupEnv("CENTRAL_AUTH_PRIVATEKEY_DATAB64")
	envTextPublicKey, presentPublicKey := os.LookupEnv("CENTRAL_AUTH_PUBLICKEY_DATAB64")
	if presentPublicKey && presentPrivateKey {
		decPrivateKey, errDecodePrivateKey := b64.StdEncoding.DecodeString(envTextPrivateKey)
		if errDecodePrivateKey != nil {
			fmt.Println("could not decode private key %s", errDecodePrivateKey)
			return
		}
		decPublicKey, errDecodePublicKey := b64.StdEncoding.DecodeString(envTextPublicKey)
		if errDecodePublicKey != nil {
			fmt.Println("could not decode public key %s", errDecodePrivateKey)
			return
		}
		os.Setenv("CENTRAL_AUTH_PRIVATEKEY_DATA", string(decPrivateKey))
		os.Setenv("CENTRAL_AUTH_PUBLICKEY_DATA", string(decPublicKey))
		fmt.Println("public and private keys decoded from base64 encoded environment")
	}
}

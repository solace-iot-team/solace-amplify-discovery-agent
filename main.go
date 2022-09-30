package main

import (
	"fmt"
	"github.com/solace-iot-team/solace-amplify-discovery-agent/pkg/cmd"
	"os"
)

func main() {
	if err := cmd.RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

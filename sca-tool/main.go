package main

import (
	"os"

	"github.com/rebaze/starter-sbom-toolchain/sca-tool/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

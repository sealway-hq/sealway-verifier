// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

// Command sealway-verifier independently verifies Sealway proofs.
//
// Run "sealway-verifier verify --help" for usage.
package main

import (
	"os"

	"github.com/sealway-hq/sealway-verifier/apps/cli/internal/cli"
)

// Build information, overridden at link time by the release pipeline.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cli.SetBuildInfo(version, commit, date)
	os.Exit(cli.Main())
}

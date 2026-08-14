// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

// Package cli implements the sealway-verifier command line interface.
//
// The command line interface is a thin adapter: it resolves paths, renders the
// report and maps the outcome to an exit code. Every verification decision is
// taken by the verifier library, so the desktop application and the future
// browser build behave identically.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/spf13/cobra"
)

// Build information, set at link time by the release pipeline.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// SetBuildInfo records the build information reported by the version command.
func SetBuildInfo(v, c, d string) {
	if v != "" {
		version = v
	}

	if c != "" {
		commit = c
	}

	if d != "" {
		date = d
	}
}

// Streams are the input and output streams the command writes to. Taking them
// as parameters is what makes the command testable without touching the
// process.
type Streams struct {
	Out io.Writer
	Err io.Writer
}

// exitError carries an explicit exit code out of a command.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

// Run executes the command line interface and returns the process exit code.
func Run(ctx context.Context, args []string, streams Streams) int {
	root := newRootCommand(streams)
	root.SetArgs(args)
	root.SetOut(streams.Out)
	root.SetErr(streams.Err)

	err := root.ExecuteContext(ctx)
	if err == nil {
		return ExitCompleteValid
	}

	var exit *exitError
	if errors.As(err, &exit) {
		if exit.err != nil && exit.code == ExitError {
			fmt.Fprintf(streams.Err, "sealway-verifier: %s\n", exit.err)
		}

		return exit.code
	}

	fmt.Fprintf(streams.Err, "sealway-verifier: %s\n", err)

	return ExitError
}

func newRootCommand(streams Streams) *cobra.Command {
	root := &cobra.Command{
		Use:   "sealway-verifier",
		Short: "Independently verify Sealway proofs",
		Long: "sealway-verifier independently verifies Sealway proofs.\n\n" +
			"It recomputes the SHA-512 of every original file, rebuilds the proof Merkle tree,\n" +
			"verifies the RFC 3161 timestamp over the proof root, recomputes the accumulator\n" +
			"inclusion proof and checks the public blockchain anchors.\n\n" +
			"The certificate is the only authoritative input: the proof manifest and the\n" +
			"timestamp token are always read from the embedded attachments it carries.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(newVerifyCommand(streams))
	root.AddCommand(newVersionCommand(streams))

	return root
}

func newVersionCommand(streams Streams) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version of sealway-verifier",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			fmt.Fprintf(streams.Out, "sealway-verifier %s (commit %s, built %s, %s %s/%s)\n",
				version, commit, date, runtime.Version(), runtime.GOOS, runtime.GOARCH)

			return nil
		},
	}
}

// Main is the entry point used by the binary.
func Main() int {
	return Run(context.Background(), os.Args[1:], Streams{Out: os.Stdout, Err: os.Stderr})
}

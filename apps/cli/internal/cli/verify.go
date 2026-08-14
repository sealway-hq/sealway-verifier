// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package cli

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sealway-hq/sealway-verifier/apps/cli/internal/render"
	"github.com/sealway-hq/sealway-verifier/packages/verifier"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/source"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/trust"
)

type verifyFlags struct {
	sources         []string
	sourcesDir      string
	jsonOutput      bool
	offline         bool
	noColor         bool
	verbose         bool
	timeout         time.Duration
	anchorEndpoints []string
	timestampRoots  string
	trustSource     string
	trustDir        string
}

func newVerifyCommand(streams Streams) *cobra.Command {
	f := &verifyFlags{}

	cmd := &cobra.Command{
		Use:   "verify <proof>",
		Short: "Verify a proof bundle or a Sealway certificate",
		Long: "Verify a Sealway proof.\n\n" +
			"The proof may be a bundle archive, which carries everything needed for a complete\n" +
			"verification, or a certificate on its own. A certificate supplied without its\n" +
			"original files still proves that the certified data is internally consistent,\n" +
			"timestamped and anchored, but the files themselves cannot be checked, so the\n" +
			"source dependent steps are reported as skipped and the result is partial.\n\n" +
			"Exit codes:\n" +
			"  0  complete verification, nothing failed\n" +
			"  1  the proof is invalid\n" +
			"  2  the tool could not run the verification\n" +
			"  3  partial verification, nothing failed but something was skipped",
		Example: "  sealway-verifier verify proof.zip\n" +
			"  sealway-verifier verify certificate.pdf\n" +
			"  sealway-verifier verify certificate.pdf --source document.pdf\n" +
			"  sealway-verifier verify certificate.pdf --source file1.pdf --source photo.jpg\n" +
			"  sealway-verifier verify certificate.pdf --sources-dir ./files\n" +
			"  sealway-verifier verify proof.zip --offline\n" +
			"  sealway-verifier verify proof.zip --json",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVerify(cmd.Context(), args[0], f, streams)
		},
	}

	flags := cmd.Flags()
	flags.StringArrayVarP(&f.sources, "source", "s", nil,
		"original file certified by the proof (repeatable)")
	flags.StringVar(&f.sourcesDir, "sources-dir", "",
		"directory holding the original files certified by the proof")
	flags.BoolVar(&f.jsonOutput, "json", false,
		"write the canonical verification report as JSON")
	flags.BoolVar(&f.offline, "offline", false,
		"disable every network call; blockchain anchor checks become skipped")
	flags.BoolVar(&f.noColor, "no-color", false,
		"disable colored output")
	flags.BoolVarP(&f.verbose, "verbose", "v", false,
		"explain successful checks as well")
	flags.DurationVar(&f.timeout, "timeout", verifier.DefaultNetworkTimeout,
		"maximum duration of a single blockchain lookup")
	flags.StringArrayVar(&f.anchorEndpoints, "anchor-endpoint", nil,
		"override the public endpoint of a network, as network=url (repeatable)")
	flags.StringVar(&f.timestampRoots, "timestamp-roots", "",
		"PEM bundle of trust anchors used to validate the timestamp signer chain")
	flags.StringVar(&f.trustSource, "trust-source", "eu",
		`where to read the European Trusted Lists from: "eu" for the official `+
			`publication, a mirror base URL, or "none" to make no claim about qualified status`)
	flags.StringVar(&f.trustDir, "trust-dir", "",
		"directory holding a trust snapshot, read instead of the network")

	return cmd
}

func runVerify(ctx context.Context, path string, f *verifyFlags, streams Streams) error {
	opts, err := buildOptions(f)
	if err != nil {
		return &exitError{code: ExitError, err: err}
	}

	input, closeInput, err := openInput(path, f)
	if err != nil {
		return &exitError{code: ExitError, err: err}
	}

	defer closeInput()

	rep, err := verifier.New(opts...).Verify(ctx, input)
	if err != nil {
		return &exitError{code: ExitError, err: err}
	}

	if f.jsonOutput {
		if err := render.JSON(streams.Out, rep); err != nil {
			return &exitError{code: ExitError, err: err}
		}
	} else {
		human := render.Options{Color: useColor(f, streams), Verbose: f.verbose}
		if err := render.Human(streams.Out, rep, human); err != nil {
			return &exitError{code: ExitError, err: err}
		}
	}

	return &exitError{code: exitCodeFor(rep.Result)}
}

func buildOptions(f *verifyFlags) ([]verifier.Option, error) {
	opts := []verifier.Option{
		verifier.WithNetworkTimeout(f.timeout),
		verifier.WithHTTPClient(&http.Client{Timeout: f.timeout}),
	}

	if f.offline {
		opts = append(opts, verifier.WithOffline())
	}

	for _, spec := range f.anchorEndpoints {
		network, endpoint, ok := strings.Cut(spec, "=")
		if !ok || strings.TrimSpace(network) == "" || strings.TrimSpace(endpoint) == "" {
			return nil, fmt.Errorf("invalid --anchor-endpoint %q: expected network=url", spec)
		}

		opts = append(opts, verifier.WithAnchorEndpoint(
			strings.ToLower(strings.TrimSpace(network)), strings.TrimSpace(endpoint)))
	}

	if f.timestampRoots != "" {
		pool, err := loadRoots(f.timestampRoots)
		if err != nil {
			return nil, err
		}

		opts = append(opts, verifier.WithTimestampRoots(pool))
	}

	trustOption, err := trustProvider(f)
	if err != nil {
		return nil, err
	}

	if trustOption != nil {
		opts = append(opts, trustOption)
	}

	return opts, nil
}

// trustProvider decides where the European Trusted Lists are read from.
//
// A snapshot on disk wins over the network, because an operator who prepared one
// meant it to be used, and it is the only source that works offline.
func trustProvider(f *verifyFlags) (verifier.Option, error) {
	if f.trustDir != "" {
		info, err := os.Stat(f.trustDir)
		if err != nil {
			return nil, fmt.Errorf("cannot read the trust snapshot %q: %w", f.trustDir, err)
		}

		if !info.IsDir() {
			return nil, fmt.Errorf("%q is not a directory", f.trustDir)
		}

		return verifier.WithTrustProvider(
			trust.NewSnapshot(os.DirFS(f.trustDir), f.trustDir)), nil
	}

	source := strings.TrimSpace(f.trustSource)

	switch {
	case source == "" || strings.EqualFold(source, "none"):
		return nil, nil
	case strings.EqualFold(source, "eu"):
		if f.offline {
			// Nothing to read and nothing to reach: qualified status will be
			// reported as indeterminate, with the reason.
			return nil, nil
		}

		return verifier.WithEUTrustLists(), nil
	case strings.HasPrefix(source, "http://"), strings.HasPrefix(source, "https://"):
		base := strings.TrimRight(source, "/")

		return verifier.WithEUTrustLists(
			trust.WithLOTLURL(base+"/lotl.xml"),
			trust.WithListURLTemplate(base+"/lists/{territory}.xml"),
		), nil
	default:
		return nil, fmt.Errorf(
			`invalid --trust-source %q: expected "eu", "none" or a mirror base URL`, source)
	}
}

func loadRoots(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read the trust anchors %q: %w", path, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificate could be read from %q", path)
	}

	return pool, nil
}

// openInput resolves the proof path into a verifier input.
//
// The input kind is decided by inspecting the leading bytes of the file rather
// than by trusting its extension, so a renamed bundle or certificate still
// verifies and a mislabelled file is refused instead of being misread.
func openInput(path string, f *verifyFlags) (verifier.Input, func(), error) {
	noop := func() {}

	file, err := os.Open(path)
	if err != nil {
		return verifier.Input{}, noop, fmt.Errorf("cannot read %q: %w", path, err)
	}

	closeFile := func() { _ = file.Close() }

	info, err := file.Stat()
	if err != nil {
		closeFile()

		return verifier.Input{}, noop, fmt.Errorf("cannot read %q: %w", path, err)
	}

	if info.IsDir() {
		closeFile()

		return verifier.Input{}, noop, fmt.Errorf("%q is a directory, not a proof", path)
	}

	kind, err := sniff(file)
	if err != nil {
		closeFile()

		return verifier.Input{}, noop, fmt.Errorf("cannot read %q: %w", path, err)
	}

	switch kind {
	case inputBundle:
		if len(f.sources) > 0 || f.sourcesDir != "" {
			closeFile()

			return verifier.Input{}, noop, errors.New(
				"a proof bundle already carries its original files, so --source and --sources-dir " +
					"cannot be used with one")
		}

		return verifier.Input{Bundle: file, BundleSize: info.Size()}, closeFile, nil

	case inputCertificate:
		sources, err := collectSources(f)
		if err != nil {
			closeFile()

			return verifier.Input{}, noop, err
		}

		return verifier.Input{Certificate: file, Sources: sources}, closeFile, nil

	default:
		closeFile()

		return verifier.Input{}, noop, fmt.Errorf(
			"%q is neither a Sealway certificate nor a proof bundle archive", path)
	}
}

type inputKind int

const (
	inputUnknown inputKind = iota
	inputCertificate
	inputBundle
)

func sniff(f *os.File) (inputKind, error) {
	var header [8]byte

	n, err := f.ReadAt(header[:], 0)
	if err != nil && n == 0 {
		return inputUnknown, err
	}

	head := header[:n]

	switch {
	case len(head) >= 5 && string(head[:5]) == "%PDF-":
		return inputCertificate, nil
	case len(head) >= 4 && head[0] == 'P' && head[1] == 'K' &&
		(head[2] == 3 || head[2] == 5 || head[2] == 7):
		return inputBundle, nil
	default:
		return inputUnknown, nil
	}
}

func collectSources(f *verifyFlags) ([]verifier.Source, error) {
	var sources []verifier.Source

	if len(f.sources) > 0 {
		explicit, err := source.FromPaths(f.sources)
		if err != nil {
			return nil, err
		}

		sources = append(sources, explicit...)
	}

	if f.sourcesDir != "" {
		discovered, err := source.FromDir(f.sourcesDir)
		if err != nil {
			return nil, err
		}

		sources = append(sources, discovered...)
	}

	return sources, nil
}

// useColor decides whether ANSI colors are written.
func useColor(f *verifyFlags, streams Streams) bool {
	_, noColorSet := os.LookupEnv("NO_COLOR")

	return colorDecision(f.noColor, f.jsonOutput, noColorSet, isTerminal(streams.Out))
}

// colorDecision holds the colour policy, separated from how its inputs are
// discovered so that it can be exercised directly.
//
// Colors are suppressed when the operator asked for it, when the output is
// machine readable, when NO_COLOR is set and when the output is not an
// interactive terminal. Status is always spelled out as well, so nothing is lost
// without them.
func colorDecision(noColorFlag, jsonOutput, noColorEnv, terminal bool) bool {
	switch {
	case noColorFlag, jsonOutput, noColorEnv:
		return false
	default:
		return terminal
	}
}

func isTerminal(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok {
		return false
	}

	info, err := file.Stat()
	if err != nil {
		return false
	}

	return info.Mode()&os.ModeCharDevice != 0
}

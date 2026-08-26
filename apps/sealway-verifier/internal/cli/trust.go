// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sealway-hq/sealway-verifier/packages/verifier/trust"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/trust/bootstrap"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/trustlist"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/trustlist/xmldsig"
)

type trustFlags struct {
	territories []string
	timeout     time.Duration
	lotlURL     string
	listURL     string
}

func newTrustCommand(streams Streams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trust",
		Short: "Work with the European Trusted List material",
		Long: "Work with the European Trusted List material used to decide whether a\n" +
			"timestamp is a qualified electronic time stamp.",
	}

	cmd.AddCommand(newTrustFetchCommand(streams))

	return cmd
}

func newTrustFetchCommand(streams Streams) *cobra.Command {
	f := &trustFlags{}

	cmd := &cobra.Command{
		Use:   "fetch <directory>",
		Short: "Download and authenticate the European Trusted Lists into a snapshot",
		Long: "Download the European List of Trusted Lists and the national lists it points\n" +
			"at, verify their signatures, and write them to a directory as a snapshot.\n\n" +
			"The snapshot holds the official signed documents unchanged, so a verifier\n" +
			"reading it checks the European signatures itself. That is what lets the same\n" +
			"snapshot be served to a browser, which cannot reach the official endpoints\n" +
			"because they send no cross-origin headers, without the server that serves it\n" +
			"becoming something anyone has to trust.\n\n" +
			"Use it with:\n" +
			"  sealway-verifier verify proof.zip --trust-dir ./trust --offline",
		Example: "  sealway-verifier trust fetch ./trust\n" +
			"  sealway-verifier trust fetch ./trust --territory ES --territory FR",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTrustFetch(cmd.Context(), args[0], f, streams)
		},
	}

	flags := cmd.Flags()
	flags.StringArrayVar(&f.territories, "territory", nil,
		"scheme territory to fetch, such as ES (repeatable; defaults to ES)")
	flags.DurationVar(&f.timeout, "timeout", 2*time.Minute,
		"maximum duration of the whole retrieval")
	flags.StringVar(&f.lotlURL, "lotl-url", bootstrap.LOTLLocation,
		"where to read the European List of Trusted Lists from")
	flags.StringVar(&f.listURL, "list-url", "",
		"where to read national lists from, with {territory} replaced by the scheme territory")

	return cmd
}

func runTrustFetch(ctx context.Context, dir string, f *trustFlags, streams Streams) error {
	territories := f.territories
	if len(territories) == 0 {
		territories = []string{"ES"}
	}

	ctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()

	fetcher, err := trust.NewFetcher(
		&http.Client{Timeout: f.timeout},
		trust.WithLOTLURL(f.lotlURL),
		trust.WithListURLTemplate(f.listURL),
	)
	if err != nil {
		return &exitError{code: ExitError, err: err}
	}

	combined := &trust.Material{Lists: map[string][]byte{}}
	sources := map[string]string{"lotl": f.lotlURL}

	for _, territory := range territories {
		territory = strings.ToUpper(strings.TrimSpace(territory))
		if territory == "" {
			continue
		}

		material, err := fetcher.Material(ctx, trust.Request{Territory: territory})
		if err != nil {
			return &exitError{
				code: ExitError,
				err:  fmt.Errorf("cannot fetch the Trusted List for %s: %w", territory, err),
			}
		}

		combined.LOTL = material.LOTL

		for t, data := range material.Lists {
			combined.Lists[t] = data
			sources[t] = "the pointer published by the European List of Trusted Lists"
		}

		fmt.Fprintf(streams.Out, "fetched and authenticated the %s Trusted List\n", territory)
	}

	if len(combined.LOTL) == 0 {
		return &exitError{code: ExitError, err: errors.New("nothing was fetched")}
	}

	if err := describe(streams, combined); err != nil {
		return &exitError{code: ExitError, err: err}
	}

	if err := writeSnapshot(dir, combined, sources); err != nil {
		return &exitError{code: ExitError, err: err}
	}

	fmt.Fprintf(streams.Out, "\nwrote the snapshot to %s\n", dir)

	return &exitError{code: ExitCompleteValid}
}

// describe reports what was fetched, so an operator sees which issue of each
// list the snapshot pins.
func describe(streams Streams, m *trust.Material) error {
	signers, err := bootstrap.LOTLSigners()
	if err != nil {
		return err
	}

	verified, err := xmldsig.Verify(m.LOTL, signers, xmldsig.Limits{})
	if err != nil {
		return fmt.Errorf("the list of lists is not authentic: %w", err)
	}

	lotl, err := trustlist.Parse(verified)
	if err != nil {
		return err
	}

	fmt.Fprintf(streams.Out, "\nEuropean List of Trusted Lists: sequence %d, issued %s\n",
		lotl.SequenceNumber, lotl.IssueDate.Format(time.RFC3339))

	for _, territory := range m.Territories() {
		pointer, ok := lotl.PointerFor(territory)
		if !ok {
			continue
		}

		list, err := xmldsig.Verify(m.Lists[territory], pointer.SigningCertificates, xmldsig.Limits{})
		if err != nil {
			return fmt.Errorf("the %s Trusted List is not authentic: %w", territory, err)
		}

		parsed, err := trustlist.Parse(list)
		if err != nil {
			return err
		}

		fmt.Fprintf(streams.Out, "%s Trusted List: sequence %d, issued %s, next update %s\n",
			territory, parsed.SequenceNumber,
			parsed.IssueDate.Format(time.RFC3339),
			parsed.NextUpdate.Format(time.RFC3339))
	}

	return nil
}

// writeSnapshot lays the material out on disk in the documented format.
func writeSnapshot(dir string, m *trust.Material, sources map[string]string) error {
	manifest := trust.BuildManifest(m, sources, time.Now())

	if err := os.MkdirAll(filepath.Join(dir, "lists"), 0o755); err != nil {
		return fmt.Errorf("cannot create %q: %w", dir, err)
	}

	if err := os.WriteFile(filepath.Join(dir, manifest.LOTL.Path), m.LOTL, 0o600); err != nil {
		return fmt.Errorf("cannot write the list of lists: %w", err)
	}

	for territory, entry := range manifest.Lists {
		path := filepath.Join(dir, filepath.FromSlash(entry.Path))
		if err := os.WriteFile(path, m.Lists[territory], 0o600); err != nil {
			return fmt.Errorf("cannot write the %s Trusted List: %w", territory, err)
		}
	}

	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot encode the manifest: %w", err)
	}

	path := filepath.Join(dir, trust.ManifestName)
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		return fmt.Errorf("cannot write the manifest: %w", err)
	}

	return nil
}

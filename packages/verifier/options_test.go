// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package verifier_test

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealway-hq/sealway-verifier/internal/prooftest"
	"github.com/sealway-hq/sealway-verifier/packages/verifier"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/anchor"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/bundle"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/pdf"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/report"
)

func TestWithBlockchainVerification(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	disabled := verifier.New(
		verifier.WithAnchorVerifier(stubAnchor{network: stubNetwork, payload: p.AccumulatorRoot}),
		verifier.WithBlockchainVerification(false),
	)

	r, err := disabled.VerifyCertificate(t.Context(),
		bytes.NewReader(p.Certificate), sourcesFor(p.Files))
	require.NoError(t, err)
	assert.Equal(t, report.StatusSkipped, statusOf(t, r, "anchors."+stubNetwork))

	enabled := verifier.New(
		verifier.WithAnchorVerifier(stubAnchor{network: stubNetwork, payload: p.AccumulatorRoot}),
		verifier.WithBlockchainVerification(true),
	)

	r, err = enabled.VerifyCertificate(t.Context(),
		bytes.NewReader(p.Certificate), sourcesFor(p.Files))
	require.NoError(t, err)
	assert.Equal(t, report.StatusValid, statusOf(t, r, "anchors."+stubNetwork))
}

// TestWithLimits checks the configured bounds actually reach the parsers, so an
// operator can tighten them for hostile input.
func TestWithLimits(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	v := verifier.New(verifier.WithOffline(), verifier.WithLimits(verifier.Limits{
		PDF: pdf.Limits{MaxAttachmentSize: 16},
	}))

	_, err := v.VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, pdf.ErrAttachmentTooLarge)
}

func TestWithLimitsAppliesToBundles(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(3)})

	archive, err := p.Bundle(prooftest.BundleOptions{})
	require.NoError(t, err)

	v := verifier.New(verifier.WithOffline(), verifier.WithLimits(verifier.Limits{
		Bundle: bundle.Limits{MaxEntries: 2},
	}))

	_, err = v.VerifyBundle(t.Context(), bytes.NewReader(archive), int64(len(archive)))
	assert.ErrorIs(t, err, bundle.ErrTooManyEntries)
}

// TestNilOptionsAreIgnored keeps constructing a verifier from a computed option
// slice safe.
func TestNilOptionsAreIgnored(t *testing.T) {
	t.Parallel()

	v := verifier.New(nil, verifier.WithOffline(), nil)
	require.NotNil(t, v)

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	r, err := v.VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), sourcesFor(p.Files))
	require.NoError(t, err)
	assert.Equal(t, report.ResultPartialValid, r.Result)
}

func TestDegenerateOptionValuesFallBackToDefaults(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	v := verifier.New(
		verifier.WithOffline(),
		verifier.WithHTTPClient(nil),
		verifier.WithNetworkTimeout(0),
		verifier.WithNetworkTimeout(-time.Second),
		verifier.WithAnchorEndpoint("", "https://example.test"),
		verifier.WithAnchorEndpoint("algorand", ""),
		verifier.WithAnchorVerifier(nil),
		verifier.WithProgress(nil),
	)

	r, err := v.VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), sourcesFor(p.Files))
	require.NoError(t, err)
	assert.Zero(t, r.Summary.Invalid)
}

// TestDefaultRegistryCoversThePublicNetworks records which networks the verifier
// can check without any configuration.
func TestDefaultRegistryCoversThePublicNetworks(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{
		Anchors: []prooftest.Anchor{
			{Network: "algorand", TransactionID: "3DZT62LVBKVIYULEPC3QGNEWVMKZEBHXA2PX7BBYU4TL7ZZI2EQQ"},
			{Network: "polygon", TransactionID: "0x" + hexOf(bytes.Repeat([]byte{0x11}, 32))},
			{Network: "base", TransactionID: "0x" + hexOf(bytes.Repeat([]byte{0x22}, 32))},
		},
		Files: prooftest.DefaultFiles(1),
	})

	// Point every provider at a closed port: the networks are supported, they are
	// simply unreachable, which must skip rather than fail.
	v := verifier.New(
		verifier.WithHTTPClient(&http.Client{Timeout: 500 * time.Millisecond}),
		verifier.WithAnchorEndpoint("algorand", "http://127.0.0.1:1"),
		verifier.WithAnchorEndpoint("polygon", "http://127.0.0.1:1"),
		verifier.WithAnchorEndpoint("base", "http://127.0.0.1:1"),
	)

	r, err := v.VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), sourcesFor(p.Files))
	require.NoError(t, err)

	for _, network := range []string{"algorand", "polygon", "base"} {
		c, ok := r.Check("anchors." + network)
		require.True(t, ok)
		assert.Equal(t, report.StatusSkipped, c.Status)
		assert.NotContains(t, c.Message, "No verifier is available",
			"%s must be supported out of the box", network)
	}
}

func TestCustomAnchorRegistryReplacesTheDefaults(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	provider, signer := trustFor(t, p)

	v := verifier.New(
		verifier.WithAnchorRegistry(anchor.Registry{
			stubNetwork: stubAnchor{network: stubNetwork, payload: p.AccumulatorRoot},
		}),
		verifier.WithTrustProvider(provider),
		verifier.WithTrustListSigners(signer),
	)

	r, err := v.VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), sourcesFor(p.Files))
	require.NoError(t, err)
	assert.Equal(t, report.ResultCompleteValid, r.Result)
}

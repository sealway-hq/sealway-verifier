// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package verifier_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mocks "github.com/sealway-hq/sealway-verifier/internal/mocks/anchor"
	"github.com/sealway-hq/sealway-verifier/internal/prooftest"
	"github.com/sealway-hq/sealway-verifier/packages/verifier"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/anchor"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/report"
)

const anchorTxID = "3DZT62LVBKVIYULEPC3QGNEWVMKZEBHXA2PX7BBYU4TL7ZZI2EQQ"

// TestAnchorProviderReceivesTheCertifiedData is what a mock is actually good
// for: it checks the arguments the pipeline hands to a provider, which a
// behavioural fake cannot observe.
//
// It matters because a provider is only as trustworthy as what it is asked to
// look for. Passing the proof root instead of the accumulator root, or losing
// the transaction identifier on the way, would still produce a green report
// against a lenient fake.
func TestAnchorProviderReceivesTheCertifiedData(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{
		Files: prooftest.DefaultFiles(1),
		Anchors: []prooftest.Anchor{{
			Network:       stubNetwork,
			TransactionID: anchorTxID,
			BlockNumber:   64055209,
		}},
	})

	m := mocks.NewMockVerifier(t)
	m.EXPECT().Network().Return(stubNetwork).Maybe()
	m.EXPECT().Endpoint().Return("mock://anchor").Maybe()

	m.EXPECT().
		Verify(
			mock.Anything,
			anchor.Anchor{
				Network:       stubNetwork,
				TransactionID: anchorTxID,
				BlockNumber:   64055209,
			},
			// The accumulator root is what is anchored on chain, never the proof
			// root.
			p.AccumulatorRoot,
		).
		Return(&anchor.Result{
			Verified:    true,
			Match:       anchor.MatchExact,
			Payload:     p.AccumulatorRoot,
			BlockNumber: 64055209,
			Endpoint:    "mock://anchor",
		}, nil).
		Once()

	provider, signer := trustFor(t, p)

	r, err := verifier.New(
		verifier.WithAnchorVerifier(m),
		verifier.WithTrustProvider(provider),
		verifier.WithTrustListSigners(signer),
	).
		VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), sourcesFor(p.Files))
	require.NoError(t, err)

	assert.Equal(t, report.ResultCompleteValid, r.Result)
	assert.Equal(t, report.StatusValid, statusOf(t, r, "anchors."+stubNetwork))

	c, _ := r.Check("anchors." + stubNetwork)
	assert.Equal(t, "mock://anchor", c.Details["endpoint"])
	assert.Equal(t, hexOf(p.AccumulatorRoot), c.Details["expected_root"])
}

// TestAnchorProviderIsCalledOncePerDeclaredAnchor checks each declared anchor is
// looked up exactly once, so a proof cannot inflate its evidence by repeating a
// network and a network is not silently skipped either.
func TestAnchorProviderIsCalledOncePerDeclaredAnchor(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{
		Files: prooftest.DefaultFiles(1),
		Anchors: []prooftest.Anchor{
			{Network: "algorand", TransactionID: anchorTxID},
			{Network: "polygon", TransactionID: "0x" + hexOf(bytes.Repeat([]byte{0x11}, 32))},
		},
	})

	algorand := mocks.NewMockVerifier(t)
	algorand.EXPECT().Network().Return("algorand").Maybe()
	algorand.EXPECT().Endpoint().Return("mock://algorand").Maybe()
	algorand.EXPECT().
		Verify(mock.Anything, mock.Anything, p.AccumulatorRoot).
		Return(&anchor.Result{Verified: true, Match: anchor.MatchExact, Payload: p.AccumulatorRoot}, nil).
		Once()

	polygon := mocks.NewMockVerifier(t)
	polygon.EXPECT().Network().Return("polygon").Maybe()
	polygon.EXPECT().Endpoint().Return("mock://polygon").Maybe()
	polygon.EXPECT().
		Verify(mock.Anything, mock.Anything, p.AccumulatorRoot).
		Return(&anchor.Result{Verified: true, Match: anchor.MatchExact, Payload: p.AccumulatorRoot}, nil).
		Once()

	provider, signer := trustFor(t, p)

	r, err := verifier.New(
		verifier.WithAnchorVerifier(algorand),
		verifier.WithAnchorVerifier(polygon),
		verifier.WithTrustProvider(provider),
		verifier.WithTrustListSigners(signer),
	).VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), sourcesFor(p.Files))
	require.NoError(t, err)

	assert.Equal(t, report.ResultCompleteValid, r.Result)
	assert.Equal(t, report.StatusValid, statusOf(t, r, "anchors.algorand"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "anchors.polygon"))
}

// TestAnchorProviderIsNotCalledWhenOffline checks that disabling the network
// really prevents the call, rather than merely relabelling its result.
func TestAnchorProviderIsNotCalledWhenOffline(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	m := mocks.NewMockVerifier(t)
	m.EXPECT().Network().Return(stubNetwork).Maybe()
	m.EXPECT().Endpoint().Return("mock://anchor").Maybe()
	// No Verify expectation: the mock fails the test if the pipeline calls it.

	r, err := verifier.New(verifier.WithAnchorVerifier(m), verifier.WithOffline()).
		VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), sourcesFor(p.Files))
	require.NoError(t, err)

	assert.Equal(t, report.StatusSkipped, statusOf(t, r, "anchors."+stubNetwork))
}

// TestAnchorLookupCarriesADeadline checks every network operation runs under a
// deadline, so a hanging endpoint can never stall a verification.
func TestAnchorLookupCarriesADeadline(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	var deadline time.Time

	var hasDeadline bool

	m := mocks.NewMockVerifier(t)
	m.EXPECT().Network().Return(stubNetwork).Maybe()
	m.EXPECT().Endpoint().Return("mock://anchor").Maybe()
	m.EXPECT().
		Verify(mock.Anything, mock.Anything, mock.Anything).
		RunAndReturn(func(ctx context.Context, _ anchor.Anchor, root []byte) (*anchor.Result, error) {
			deadline, hasDeadline = ctx.Deadline()

			return &anchor.Result{Verified: true, Match: anchor.MatchExact, Payload: root}, nil
		}).
		Once()

	_, err := verifier.New(
		verifier.WithAnchorVerifier(m),
		verifier.WithNetworkTimeout(3*time.Second),
	).VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), sourcesFor(p.Files))
	require.NoError(t, err)

	require.True(t, hasDeadline, "an anchor lookup must always run under a deadline")
	assert.WithinDuration(t, time.Now().Add(3*time.Second), deadline, 2*time.Second)
}

// The generated mocks must keep satisfying the public provider interface, which
// is also what makes a third-party implementation a drop-in replacement.
var _ anchor.Verifier = (*mocks.MockVerifier)(nil)

var _ anchor.HTTPClient = (*mocks.MockHTTPClient)(nil)

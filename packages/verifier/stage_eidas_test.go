// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package verifier_test

import (
	"bytes"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealway-hq/sealway-verifier/internal/prooftest"
	"github.com/sealway-hq/sealway-verifier/packages/verifier"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/report"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/trust"
)

// eidasProof is a generated proof together with a trust snapshot describing the
// authority that timestamped it.
type eidasProof struct {
	proof    *prooftest.Proof
	scheme   *prooftest.TrustScheme
	provider trust.Provider
}

// newEIDASProof builds a proof whose timestamp was produced by a service the
// generated Trusted List publishes with the given status.
func newEIDASProof(t *testing.T, status string, statusSince time.Time) *eidasProof {
	t.Helper()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	scheme, err := prooftest.NewTrustScheme("ES")
	require.NoError(t, err)

	service := prooftest.TrustService{
		ProviderName: "Test Trust Services",
		ServiceName:  "Qualified electronic time stamps",
		Identity:     p.TSA.RootCert,
		Status:       status,
		StatusSince:  statusSince,
	}

	lotl, err := scheme.LOTL(prooftest.LOTLOptions{})
	require.NoError(t, err)

	list, err := scheme.TrustList(prooftest.TrustListOptions{
		Services: []prooftest.TrustService{service},
	})
	require.NoError(t, err)

	files, err := prooftest.SnapshotFiles(lotl, map[string][]byte{"ES": list})
	require.NoError(t, err)

	mapFS := fstest.MapFS{}
	for name, data := range files {
		mapFS[name] = &fstest.MapFile{Data: data}
	}

	return &eidasProof{
		proof:    p,
		scheme:   scheme,
		provider: trust.NewSnapshot(mapFS, "test snapshot"),
	}
}

// verify runs a verification with the trust snapshot wired in.
func (e *eidasProof) verify(t *testing.T) *report.Report {
	t.Helper()

	v := verifier.New(
		verifier.WithOffline(),
		verifier.WithTrustProvider(e.provider),
		verifier.WithTrustListSigners(e.scheme.LOTLSigner.Certificate),
	)

	r, err := v.VerifyCertificate(t.Context(),
		bytes.NewReader(e.proof.Certificate), sourcesFor(e.proof.Files))
	require.NoError(t, err)

	return r
}

// TestQualifiedTimestampIsReported is the headline case: the pipeline answers
// the question the whole subsystem exists for.
func TestQualifiedTimestampIsReported(t *testing.T) {
	t.Parallel()

	e := newEIDASProof(t, prooftest.StatusGranted,
		time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC))

	r := e.verify(t)

	assert.Equal(t, report.StatusValid, statusOf(t, r, "timestamp.qualified"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "timestamp.trust_chain"))

	c, _ := r.Check("timestamp.qualified")
	assert.Equal(t, "qualified", c.Details["determination"])
	assert.Equal(t, "granted", c.Details["service_status"])
	assert.Equal(t, "QTST", c.Details["service_type"])
	assert.Equal(t, "ES", c.Details["trust_list"])
	assert.Contains(t, c.Message, "qualified electronic time stamp")
}

// TestWithdrawnServiceMakesTheTimestampNotQualified checks a recognition that
// had ended is reported as a failure of the qualified claim, not as an unknown.
func TestWithdrawnServiceMakesTheTimestampNotQualified(t *testing.T) {
	t.Parallel()

	e := newEIDASProof(t, prooftest.StatusWithdrawn,
		prooftest.DefaultGenTime.Add(-48*time.Hour))

	r := e.verify(t)

	assert.Equal(t, report.StatusInvalid, statusOf(t, r, "timestamp.qualified"))
	assert.Equal(t, report.ResultInvalid, r.Result)
}

// TestQualifiedStatusIsIndeterminateWithoutATrustSource records the default when
// nothing was configured: the question is left open rather than answered from
// the issuer's own claim.
func TestQualifiedStatusIsIndeterminateWithoutATrustSource(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	r, err := verifier.New(verifier.WithOffline()).
		VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), sourcesFor(p.Files))
	require.NoError(t, err)

	c, ok := r.Check("timestamp.qualified")
	require.True(t, ok)
	assert.Equal(t, report.StatusIndeterminate, c.Status)
	assert.Contains(t, c.Message, "No Trusted List source was configured")

	// An indeterminate step never yields a complete verification.
	assert.Equal(t, report.ResultPartialValid, r.Result)
}

// TestQualifiedStatementAloneIsNeverEnough is the overclaiming guard: a token
// asserting its own qualified status does not become qualified.
func TestQualifiedStatementAloneIsNeverEnough(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	r, err := verifier.New(verifier.WithOffline()).
		VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), sourcesFor(p.Files))
	require.NoError(t, err)

	c, _ := r.Check("timestamp.qualified")
	assert.NotEqual(t, report.StatusValid, c.Status)
}

// TestUnauthenticTrustListLeavesTheQuestionOpen checks a list that does not
// verify is refused, and that refusing it is not the same as denying
// qualification.
func TestUnauthenticTrustListLeavesTheQuestionOpen(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	scheme, err := prooftest.NewTrustScheme("ES")
	require.NoError(t, err)

	lotl, err := scheme.LOTL(prooftest.LOTLOptions{})
	require.NoError(t, err)

	list, err := scheme.TrustList(prooftest.TrustListOptions{
		Services: []prooftest.TrustService{{
			ProviderName: "Test Trust Services",
			ServiceName:  "Qualified electronic time stamps",
			Identity:     p.TSA.RootCert,
			Status:       prooftest.StatusGranted,
		}},
		CorruptSignature: true,
	})
	require.NoError(t, err)

	files, err := prooftest.SnapshotFiles(lotl, map[string][]byte{"ES": list})
	require.NoError(t, err)

	mapFS := fstest.MapFS{}
	for name, data := range files {
		mapFS[name] = &fstest.MapFile{Data: data}
	}

	v := verifier.New(
		verifier.WithOffline(),
		verifier.WithTrustProvider(trust.NewSnapshot(mapFS, "test snapshot")),
		verifier.WithTrustListSigners(scheme.LOTLSigner.Certificate),
	)

	r, err := v.VerifyCertificate(t.Context(),
		bytes.NewReader(p.Certificate), sourcesFor(p.Files))
	require.NoError(t, err)

	c, _ := r.Check("timestamp.qualified")
	assert.Equal(t, report.StatusIndeterminate, c.Status)
	assert.Contains(t, c.Message, "not authentic")

	// The proof itself is untouched by the trust material being unusable.
	assert.Equal(t, report.StatusValid, statusOf(t, r, "timestamp.imprint"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "proof_merkle.root"))
	assert.NotEqual(t, report.ResultInvalid, r.Result)
}

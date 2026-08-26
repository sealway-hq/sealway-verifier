// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package verifier_test

import (
	"bytes"
	"context"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"

	"github.com/sealway-hq/sealway-verifier/internal/prooftest"
	"github.com/sealway-hq/sealway-verifier/packages/verifier"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/anchor"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/report"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/trust"
)

func sourceFor(f prooftest.File) verifier.Source {
	return verifier.Source{
		Name:     f.Name,
		Size:     int64(len(f.Content)),
		Explicit: true,
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(f.Content)), nil
		},
	}
}

func sourcesFor(files []prooftest.File) []verifier.Source {
	out := make([]verifier.Source, 0, len(files))
	for _, f := range files {
		out = append(out, sourceFor(f))
	}

	return out
}

// stubNetwork is the network the generated proofs are anchored on. Anchor
// lookups are served by a stub so that the test suite never depends on a live
// public network.
const stubNetwork = "algorand"

func newProof(t *testing.T, opts prooftest.Options) *prooftest.Proof {
	t.Helper()

	if opts.Anchors == nil {
		opts.Anchors = []prooftest.Anchor{{
			Network:       stubNetwork,
			TransactionID: "3DZT62LVBKVIYULEPC3QGNEWVMKZEBHXA2PX7BBYU4TL7ZZI2EQQ",
			BlockNumber:   64055209,
		}}
	}

	// A proof that carries its revocation evidence is what a complete one looks
	// like. A test that wants the opposite builds it without.
	if opts.Revocation == nil {
		opts.Revocation = &prooftest.RevocationOptions{Status: ocsp.Good}
	}

	p, err := prooftest.New(opts)
	require.NoError(t, err)

	return p
}

// stubAnchor answers anchor lookups from memory.
type stubAnchor struct {
	network string
	payload []byte
	err     error
}

func (s stubAnchor) Network() string  { return s.network }
func (s stubAnchor) Endpoint() string { return "stub://anchor" }

func (s stubAnchor) Verify(_ context.Context, _ anchor.Anchor, expected []byte) (*anchor.Result, error) {
	if s.err != nil {
		return nil, s.err
	}

	match := anchor.Classify(s.payload, expected)

	return &anchor.Result{
		Verified:    match != anchor.MatchNone,
		Match:       match,
		Payload:     s.payload,
		BlockNumber: 64055209,
		Endpoint:    s.Endpoint(),
	}, nil
}

// offline verifies without any network access, so anchor checks are skipped.
func offline() *verifier.Verifier { return verifier.New(verifier.WithOffline()) }

// anchored verifies with a stub that serves the anchored payload of p and with a
// Trusted List recognising the authority that timestamped it.
//
// Both are needed for a complete verification: leaving either out means a step
// could not be established, and a run where something is unestablished is
// reported as partial rather than complete.
func anchored(t *testing.T, p *prooftest.Proof) *verifier.Verifier {
	t.Helper()

	provider, signer := trustFor(t, p)

	return verifier.New(
		verifier.WithAnchorVerifier(stubAnchor{network: stubNetwork, payload: p.AccumulatorRoot}),
		verifier.WithTrustProvider(provider),
		verifier.WithTrustListSigners(signer),
	)
}

// trustFor builds a Trusted List snapshot recognising the throwaway authority
// that signed the timestamp of p.
func trustFor(t *testing.T, p *prooftest.Proof) (trust.Provider, *x509.Certificate) {
	t.Helper()

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
			StatusSince:  time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC),
		}},
	})
	require.NoError(t, err)

	files, err := prooftest.SnapshotFiles(lotl, map[string][]byte{"ES": list})
	require.NoError(t, err)

	mapFS := fstest.MapFS{}
	for name, data := range files {
		mapFS[name] = &fstest.MapFile{Data: data}
	}

	return trust.NewSnapshot(mapFS, "test snapshot"), scheme.LOTLSigner.Certificate
}

func statusOf(t *testing.T, r *report.Report, id string) report.Status {
	t.Helper()

	c, ok := r.Check(id)
	require.True(t, ok, "check %q is missing from the report", id)

	return c.Status
}

func TestHashSource(t *testing.T) {
	t.Parallel()

	t.Run("empty file", func(t *testing.T) {
		t.Parallel()

		sum, err := verifier.HashSource(bytes.NewReader(nil))
		require.NoError(t, err)

		expected := sha512.Sum512(nil)
		assert.Equal(t, expected[:], sum)
		assert.Len(t, sum, 64)
	})

	t.Run("known vector", func(t *testing.T) {
		t.Parallel()

		// FIPS 180-4 test vector for SHA-512 of "abc".
		sum, err := verifier.HashSource(strings.NewReader("abc"))
		require.NoError(t, err)
		assert.Equal(t,
			"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"+
				"2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
			hexOf(sum))
	})

	t.Run("streamed large input", func(t *testing.T) {
		t.Parallel()

		const size = 5 << 20

		data := bytes.Repeat([]byte("sealway"), size/7)

		streamed, err := verifier.HashSource(bytes.NewReader(data))
		require.NoError(t, err)

		atOnce := sha512.Sum512(data)
		assert.Equal(t, atOnce[:], streamed)
	})

	t.Run("deterministic", func(t *testing.T) {
		t.Parallel()

		first, err := verifier.HashSource(strings.NewReader("payload"))
		require.NoError(t, err)

		second, err := verifier.HashSource(strings.NewReader("payload"))
		require.NoError(t, err)
		assert.Equal(t, first, second)
	})

	t.Run("different content differs", func(t *testing.T) {
		t.Parallel()

		a, err := verifier.HashSource(strings.NewReader("payload"))
		require.NoError(t, err)

		b, err := verifier.HashSource(strings.NewReader("payloae"))
		require.NoError(t, err)
		assert.NotEqual(t, a, b)
	})

	t.Run("read failure", func(t *testing.T) {
		t.Parallel()

		_, err := verifier.HashSource(failingReader{})
		assert.Error(t, err)
	})
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"

	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}

	return string(out)
}

func TestVerifyBundleComplete(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(3)})

	archive, err := p.Bundle(prooftest.BundleOptions{})
	require.NoError(t, err)

	r, err := anchored(t, p).VerifyBundle(t.Context(), bytes.NewReader(archive), int64(len(archive)))
	require.NoError(t, err)

	assert.Equal(t, report.ResultCompleteValid, r.Result)
	assert.Equal(t, report.StatusValid, statusOf(t, r, "anchors."+stubNetwork))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "proof_merkle.root"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "proof_merkle.leaf_hashes"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "proof_merkle.item_proofs"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "timestamp.imprint"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "timestamp.signature"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "accumulator.root"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "certificate.loose_copies"))

	require.NotNil(t, r.Certificate)
	assert.Equal(t, p.PublicID, r.Certificate.PublicID)
	assert.Equal(t, 3, r.Certificate.ItemCount)
}

// TestRevocationIsEstablishedFromEmbeddedEvidence is the case the check exists
// for: a proof carrying a signed statement of its signing certificate's status
// answers the question with no network at all, which is what makes it answerable
// from a browser.
func TestRevocationIsEstablishedFromEmbeddedEvidence(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	archive, err := p.Bundle(prooftest.BundleOptions{})
	require.NoError(t, err)

	r, err := anchored(t, p).VerifyBundle(t.Context(), bytes.NewReader(archive), int64(len(archive)))
	require.NoError(t, err)

	c, ok := r.Check("timestamp.revocation")
	require.True(t, ok)

	assert.Equal(t, report.StatusValid, c.Status)
	assert.Equal(t, "good", c.Details["status"])
	assert.Equal(t, report.ResultCompleteValid, r.Result,
		"a proof carrying its evidence leaves nothing unestablished")
}

// TestRevocationBeforeTheAssertedTimeInvalidatesTheProof is the finding the
// check is worth having for: the certificate was already withdrawn when it
// signed, so what it signed proves nothing.
func TestRevocationBeforeTheAssertedTimeInvalidatesTheProof(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{
		Files: prooftest.DefaultFiles(1),
		Revocation: &prooftest.RevocationOptions{
			Status: ocsp.Revoked,
			Reason: ocsp.KeyCompromise,
		},
	})

	archive, err := p.Bundle(prooftest.BundleOptions{})
	require.NoError(t, err)

	r, err := anchored(t, p).VerifyBundle(t.Context(), bytes.NewReader(archive), int64(len(archive)))
	require.NoError(t, err)

	assert.Equal(t, report.StatusInvalid, statusOf(t, r, "timestamp.revocation"))
	assert.Equal(t, report.ResultInvalid, r.Result)
}

// TestRevocationAfterTheAssertedTimeDoesNotBreakTheProof keeps a rotated
// certificate from retroactively destroying every proof an authority ever made.
func TestRevocationAfterTheAssertedTimeDoesNotBreakTheProof(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{
		Files: prooftest.DefaultFiles(1),
		Revocation: &prooftest.RevocationOptions{
			Status:    ocsp.Revoked,
			Reason:    ocsp.Superseded,
			RevokedAt: prooftest.DefaultGenTime.Add(72 * time.Hour),
		},
	})

	archive, err := p.Bundle(prooftest.BundleOptions{})
	require.NoError(t, err)

	r, err := anchored(t, p).VerifyBundle(t.Context(), bytes.NewReader(archive), int64(len(archive)))
	require.NoError(t, err)

	c, ok := r.Check("timestamp.revocation")
	require.True(t, ok)

	assert.Equal(t, report.StatusValid, c.Status)
	assert.Equal(t, "revoked_later", c.Details["status"])
	assert.Equal(t, "superseded", c.Details["revocation_reason"])
	assert.Equal(t, report.ResultCompleteValid, r.Result)
}

// TestCompromiseAfterTheAssertedTimeIsUndecided is the exception to the rule
// above, and the reason it cannot simply be "later revocations do not count".
func TestCompromiseAfterTheAssertedTimeIsUndecided(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{
		Files: prooftest.DefaultFiles(1),
		Revocation: &prooftest.RevocationOptions{
			Status:    ocsp.Revoked,
			Reason:    ocsp.KeyCompromise,
			RevokedAt: prooftest.DefaultGenTime.Add(72 * time.Hour),
		},
	})

	archive, err := p.Bundle(prooftest.BundleOptions{})
	require.NoError(t, err)

	r, err := anchored(t, p).VerifyBundle(t.Context(), bytes.NewReader(archive), int64(len(archive)))
	require.NoError(t, err)

	assert.Equal(t, report.StatusIndeterminate, statusOf(t, r, "timestamp.revocation"),
		"a compromise may predate the signature; nothing establishes that it did not")
	assert.NotEqual(t, report.ResultInvalid, r.Result)
}

// TestRevocationWithoutEvidenceIsUnestablished states what a proof made before
// the evidence was captured reports.
//
// This is not a limitation of the verifier: the status of a certificate at a
// past instant cannot be reconstructed afterwards. The honest answer is that the
// question was not settled — never that it was fine.
func TestRevocationWithoutEvidenceIsUnestablished(t *testing.T) {
	t.Parallel()

	bare, err := prooftest.New(prooftest.Options{
		Files: prooftest.DefaultFiles(1),
		Anchors: []prooftest.Anchor{{
			Network:       stubNetwork,
			TransactionID: "3DZT62LVBKVIYULEPC3QGNEWVMKZEBHXA2PX7BBYU4TL7ZZI2EQQ",
			BlockNumber:   64055209,
		}},
	})
	require.NoError(t, err)

	archive, err := bare.Bundle(prooftest.BundleOptions{})
	require.NoError(t, err)

	r, err := anchored(t, bare).VerifyBundle(t.Context(), bytes.NewReader(archive), int64(len(archive)))
	require.NoError(t, err)

	c, ok := r.Check("timestamp.revocation")
	require.True(t, ok)

	assert.Equal(t, report.StatusSkipped, c.Status)
	assert.True(t, c.AffectsCompleteness,
		"missing evidence is a gap in the proof, not a documented scope limit")
	assert.Equal(t, report.ResultPartialValid, r.Result)

	// Whatever it could not establish, the reader is told where to look.
	assert.NotEmpty(t, c.Details["ocsp_responders"])
}

// TestUnauthorisedResponderIsRefused closes the gap the parsing library leaves:
// a certificate the authority signed is not thereby entitled to answer for it.
func TestUnauthorisedResponderIsRefused(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{
		Files: prooftest.DefaultFiles(1),
		Revocation: &prooftest.RevocationOptions{
			Status:               ocsp.Good,
			DelegatedResponder:   true,
			OmitOCSPSigningUsage: true,
		},
	})

	archive, err := p.Bundle(prooftest.BundleOptions{})
	require.NoError(t, err)

	r, err := anchored(t, p).VerifyBundle(t.Context(), bytes.NewReader(archive), int64(len(archive)))
	require.NoError(t, err)

	assert.Equal(t, report.StatusIndeterminate, statusOf(t, r, "timestamp.revocation"))
}

// TestTamperedEvidenceIsRefused keeps supplied evidence material rather than
// authority: it is checked before anything it says is read.
func TestTamperedEvidenceIsRefused(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{
		Files:      prooftest.DefaultFiles(1),
		Revocation: &prooftest.RevocationOptions{Status: ocsp.Good, Corrupt: true},
	})

	archive, err := p.Bundle(prooftest.BundleOptions{})
	require.NoError(t, err)

	r, err := anchored(t, p).VerifyBundle(t.Context(), bytes.NewReader(archive), int64(len(archive)))
	require.NoError(t, err)

	assert.Equal(t, report.StatusIndeterminate, statusOf(t, r, "timestamp.revocation"))
}

// TestRevocationIsReportedEvenWhenTheTokenIsUnreadable keeps the shape of the
// report independent of the outcome.
func TestRevocationIsReportedEvenWhenTheTokenIsUnreadable(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1), Token: []byte("not a token")})

	archive, err := p.Bundle(prooftest.BundleOptions{})
	require.NoError(t, err)

	r, err := offline().VerifyBundle(t.Context(), bytes.NewReader(archive), int64(len(archive)))
	require.NoError(t, err)

	c, ok := r.Check("timestamp.revocation")
	require.True(t, ok, "the identifier is present even when nothing could be read")
	assert.Equal(t, report.StatusSkipped, c.Status)
}

func TestVerifyCertificateWithSources(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(2)})

	r, err := anchored(t, p).VerifyCertificate(t.Context(),
		bytes.NewReader(p.Certificate), sourcesFor(p.Files))
	require.NoError(t, err)

	assert.Equal(t, report.ResultCompleteValid, r.Result)
	assert.Equal(t, report.StatusValid, statusOf(t, r, "sources.item.0"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "sources.item.1"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "proof_merkle.root"))
}

// TestVerifyCertificateAloneIsPartial pins the central promise of a partial
// verification: everything that does not need the files is still verified, and
// what does is skipped with a reason rather than assumed.
func TestVerifyCertificateAloneIsPartial(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(2)})

	r, err := offline().VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), nil)
	require.NoError(t, err)

	assert.Equal(t, report.ResultPartialValid, r.Result)

	assert.Equal(t, report.StatusSkipped, statusOf(t, r, "sources.availability"))
	assert.Equal(t, report.StatusSkipped, statusOf(t, r, "proof_merkle.root"))
	assert.Equal(t, report.StatusSkipped, statusOf(t, r, "proof_merkle.leaf_hashes"))

	// Everything independent of the original files is still verified.
	assert.Equal(t, report.StatusValid, statusOf(t, r, "proof_merkle.certified_root"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "proof_merkle.item_proofs"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "timestamp.imprint"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "accumulator.inclusion_proof"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "accumulator.root"))

	// The report must say plainly that a verified inclusion path over certified
	// leaves is not evidence about a file that was never supplied.
	c, ok := r.Check("proof_merkle.item_proofs")
	require.True(t, ok)
	assert.Contains(t, c.Message, "not evidence")
}

func TestVerifyCertificateWithWrongSource(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	wrong := sourceFor(prooftest.File{Name: p.Files[0].Name, Content: []byte("tampered content")})

	r, err := offline().VerifyCertificate(t.Context(),
		bytes.NewReader(p.Certificate), []verifier.Source{wrong})
	require.NoError(t, err)

	assert.Equal(t, report.ResultInvalid, r.Result)
	assert.Equal(t, report.StatusInvalid, statusOf(t, r, "sources.item.0"))

	// A failing source must not stop the rest of the pipeline: the timestamp and
	// the accumulator are still verified so the report stays diagnostic.
	assert.Equal(t, report.StatusValid, statusOf(t, r, "timestamp.imprint"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "accumulator.root"))
	assert.Equal(t, report.StatusSkipped, statusOf(t, r, "proof_merkle.root"))
}

func TestVerifyRejectsUnrelatedExplicitSource(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	unrelated := sourceFor(prooftest.File{Name: "holiday.jpg", Content: []byte("unrelated")})

	r, err := offline().VerifyCertificate(t.Context(),
		bytes.NewReader(p.Certificate), []verifier.Source{unrelated})
	require.NoError(t, err)

	assert.Equal(t, report.ResultInvalid, r.Result)
	assert.Equal(t, report.StatusInvalid, statusOf(t, r, "sources.unmatched"))
	assert.Equal(t, report.StatusSkipped, statusOf(t, r, "sources.item.0"))
}

// TestVerifyIgnoresUnrelatedDiscoveredSource records the deliberate difference
// between a file the caller designated and one merely found in a directory.
func TestVerifyIgnoresUnrelatedDiscoveredSource(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	discovered := sourceFor(prooftest.File{Name: "holiday.jpg", Content: []byte("unrelated")})
	discovered.Explicit = false

	sources := append(sourcesFor(p.Files), discovered)

	r, err := anchored(t, p).VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), sources)
	require.NoError(t, err)

	assert.Equal(t, report.ResultCompleteValid, r.Result)
	_, ok := r.Check("sources.unmatched")
	assert.False(t, ok)
}

// TestVerifyMatchesRenamedSourceByContent checks the content addressed fallback:
// the digest, not the name, is the authoritative link to a certified item.
func TestVerifyMatchesRenamedSourceByContent(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	renamed := sourceFor(prooftest.File{
		Name:    "renamed-by-the-user.bin",
		Content: p.Files[0].Content,
	})

	r, err := anchored(t, p).VerifyCertificate(t.Context(),
		bytes.NewReader(p.Certificate), []verifier.Source{renamed})
	require.NoError(t, err)

	assert.Equal(t, report.ResultCompleteValid, r.Result)

	c, ok := r.Check("sources.item.0")
	require.True(t, ok)
	assert.Equal(t, "content", c.Details["matched_by"])
}

func TestVerifyDetectsTamperedManifest(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		mutate func(m map[string]any)
		check  string
	}{
		"leaf hash replaced": {
			mutate: func(m map[string]any) {
				item := m["items"].([]any)[0].(map[string]any)
				item["leaf_hash"] = strings.Repeat("ab", 64)
				item["hash_sha512"] = strings.Repeat("ab", 64)
			},
			check: "proof_merkle.certified_root",
		},
		"accumulator root replaced": {
			mutate: func(m map[string]any) {
				m["notarization"].(map[string]any)["accumulator_root"] = strings.Repeat("cd", 64)
			},
			check: "accumulator.root",
		},
		"inclusion path replaced": {
			mutate: func(m map[string]any) {
				p := m["notarization"].(map[string]any)["inclusion_proof"].(map[string]any)
				p["siblings"].([]any)[0].(map[string]any)["hash"] = strings.Repeat("ef", 64)
			},
			check: "accumulator.inclusion_proof",
		},
		"item inclusion path replaced": {
			mutate: func(m map[string]any) {
				item := m["items"].([]any)[0].(map[string]any)
				p := item["merkle_proof"].(map[string]any)
				p["siblings"].([]any)[0].(map[string]any)["hash"] = strings.Repeat("ef", 64)
			},
			check: "proof_merkle.item_proofs",
		},
		"declared timestamp serial replaced": {
			mutate: func(m map[string]any) {
				ts := m["notarization"].(map[string]any)["proof_timestamp"].(map[string]any)
				ts["serial_number"] = "999"
			},
			check: "timestamp.metadata",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			p := newProof(t, prooftest.Options{
				Files:          prooftest.DefaultFiles(1),
				MutateManifest: tc.mutate,
			})

			r, err := offline().VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), nil)
			require.NoError(t, err)

			assert.Equal(t, report.ResultInvalid, r.Result)
			assert.Equal(t, report.StatusInvalid, statusOf(t, r, tc.check))
		})
	}
}

func TestVerifyDetectsStructurallyInvalidManifest(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{
		Files: prooftest.DefaultFiles(1),
		MutateManifest: func(m map[string]any) {
			m["version"] = "9.0"
		},
	})

	r, err := offline().VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), nil)
	require.NoError(t, err)

	assert.Equal(t, report.ResultInvalid, r.Result)
	assert.Equal(t, report.StatusInvalid, statusOf(t, r, "certificate.manifest_schema"))

	c, _ := r.Check("certificate.manifest_schema")
	assert.NotEmpty(t, c.Details)
}

func TestVerifyDetectsTamperedTimestamp(t *testing.T) {
	t.Parallel()

	t.Run("imprint over another digest", func(t *testing.T) {
		t.Parallel()

		p := newProof(t, prooftest.Options{
			Files: prooftest.DefaultFiles(1),
			TokenOptions: &prooftest.TokenOptions{
				Imprint: bytes.Repeat([]byte{0x42}, 64),
			},
		})

		r, err := offline().VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), nil)
		require.NoError(t, err)

		assert.Equal(t, report.ResultInvalid, r.Result)
		assert.Equal(t, report.StatusInvalid, statusOf(t, r, "timestamp.imprint"))
		assert.Equal(t, report.StatusValid, statusOf(t, r, "timestamp.signature"))
	})

	t.Run("corrupted signature", func(t *testing.T) {
		t.Parallel()

		p := newProof(t, prooftest.Options{
			Files:        prooftest.DefaultFiles(1),
			TokenOptions: &prooftest.TokenOptions{CorruptSignature: true},
		})

		r, err := offline().VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), nil)
		require.NoError(t, err)

		assert.Equal(t, report.ResultInvalid, r.Result)
		assert.Equal(t, report.StatusInvalid, statusOf(t, r, "timestamp.signature"))
	})

	t.Run("malformed artifact", func(t *testing.T) {
		t.Parallel()

		p := newProof(t, prooftest.Options{
			Files: prooftest.DefaultFiles(1),
			Token: []byte("this is not a DER encoded timestamp"),
		})

		r, err := offline().VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), nil)
		require.NoError(t, err)

		assert.Equal(t, report.ResultInvalid, r.Result)
		assert.Equal(t, report.StatusInvalid, statusOf(t, r, "timestamp.structure"))
		assert.Equal(t, report.StatusSkipped, statusOf(t, r, "timestamp.signature"))
	})
}

func TestVerifyDetectsMissingArtifacts(t *testing.T) {
	t.Parallel()

	t.Run("no manifest", func(t *testing.T) {
		t.Parallel()

		p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1), OmitManifest: true})

		r, err := offline().VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), nil)
		require.NoError(t, err)

		assert.Equal(t, report.ResultInvalid, r.Result)
		assert.Equal(t, report.StatusInvalid, statusOf(t, r, "certificate.manifest"))
		assert.Equal(t, report.StatusSkipped, statusOf(t, r, "sources.availability"))
	})

	t.Run("no timestamp", func(t *testing.T) {
		t.Parallel()

		p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1), OmitToken: true})

		r, err := offline().VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), nil)
		require.NoError(t, err)

		assert.Equal(t, report.ResultInvalid, r.Result)
		assert.Equal(t, report.StatusInvalid, statusOf(t, r, "certificate.timestamp_token"))
		assert.Equal(t, report.StatusSkipped, statusOf(t, r, "timestamp.imprint"))
	})
}

// TestLooseCopiesAreNeverAuthoritative is the architectural guarantee: a bundle
// whose loose copies disagree with the certificate is still verified from the
// certificate, and the disagreement is reported rather than acted upon.
func TestLooseCopiesAreNeverAuthoritative(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	tampered := bytes.Replace(p.Manifest,
		[]byte(`"public_id": "`+p.PublicID+`"`),
		[]byte(`"public_id": "SW-2026-FORGED0"`), 1)
	require.NotEqual(t, string(p.Manifest), string(tampered))

	archive, err := p.Bundle(prooftest.BundleOptions{LooseManifest: tampered})
	require.NoError(t, err)

	r, err := offline().VerifyBundle(t.Context(), bytes.NewReader(archive), int64(len(archive)))
	require.NoError(t, err)

	// The certificate still drives every cryptographic conclusion.
	assert.Equal(t, p.PublicID, r.Certificate.PublicID)
	assert.Equal(t, report.StatusValid, statusOf(t, r, "proof_merkle.root"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "timestamp.imprint"))

	// The contradiction is surfaced.
	assert.Equal(t, report.StatusInvalid, statusOf(t, r, "certificate.loose_copies"))
}

func TestBundleWithoutLooseCopiesStillVerifies(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	archive, err := p.Bundle(prooftest.BundleOptions{OmitLooseCopies: true})
	require.NoError(t, err)

	r, err := anchored(t, p).VerifyBundle(t.Context(), bytes.NewReader(archive), int64(len(archive)))
	require.NoError(t, err)

	assert.Equal(t, report.ResultCompleteValid, r.Result)
	assert.Equal(t, report.StatusSkipped, statusOf(t, r, "certificate.loose_copies"))
}

func TestBundleWithoutSourcesIsPartial(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	archive, err := p.Bundle(prooftest.BundleOptions{OmitSources: true})
	require.NoError(t, err)

	r, err := offline().VerifyBundle(t.Context(), bytes.NewReader(archive), int64(len(archive)))
	require.NoError(t, err)

	assert.Equal(t, report.ResultPartialValid, r.Result)
	assert.Equal(t, report.StatusSkipped, statusOf(t, r, "sources.availability"))
}

func TestBundleOperationalErrors(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	t.Run("no certificate", func(t *testing.T) {
		t.Parallel()

		archive, err := p.Bundle(prooftest.BundleOptions{OmitCertificate: true})
		require.NoError(t, err)

		_, err = offline().VerifyBundle(t.Context(), bytes.NewReader(archive), int64(len(archive)))
		assert.Error(t, err)
	})

	t.Run("ambiguous certificates", func(t *testing.T) {
		t.Parallel()

		archive, err := p.Bundle(prooftest.BundleOptions{ExtraCertificates: 2})
		require.NoError(t, err)

		_, err = offline().VerifyBundle(t.Context(), bytes.NewReader(archive), int64(len(archive)))
		assert.Error(t, err)
	})

	t.Run("zip slip attempt", func(t *testing.T) {
		t.Parallel()

		archive, err := p.Bundle(prooftest.BundleOptions{
			ExtraEntries: map[string][]byte{"../../escaped.txt": []byte("payload")},
		})
		require.NoError(t, err)

		_, err = offline().VerifyBundle(t.Context(), bytes.NewReader(archive), int64(len(archive)))
		assert.Error(t, err)
	})
}

func TestVerifyInputValidation(t *testing.T) {
	t.Parallel()

	v := offline()

	cases := map[string]verifier.Input{
		"nothing supplied": {},
		"both supplied": {
			Bundle:      bytes.NewReader([]byte("x")),
			BundleSize:  1,
			Certificate: bytes.NewReader([]byte("x")),
		},
		"bundle without size": {Bundle: bytes.NewReader([]byte("x"))},
		"bundle with sources": {
			Bundle:     bytes.NewReader([]byte("x")),
			BundleSize: 1,
			Sources:    []verifier.Source{{Name: "a", Open: func() (io.ReadCloser, error) { return nil, nil }}},
		},
		"source without name": {
			Certificate: bytes.NewReader([]byte("x")),
			Sources:     []verifier.Source{{Open: func() (io.ReadCloser, error) { return nil, nil }}},
		},
		"source without reader": {
			Certificate: bytes.NewReader([]byte("x")),
			Sources:     []verifier.Source{{Name: "a"}},
		},
	}

	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := v.Verify(t.Context(), in)
			require.Error(t, err)
			assert.ErrorIs(t, err, verifier.ErrInvalidInput)
		})
	}
}

func TestVerifyDispatchesOnInput(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	archive, err := p.Bundle(prooftest.BundleOptions{})
	require.NoError(t, err)

	r, err := anchored(t, p).Verify(t.Context(), verifier.Input{
		Bundle:     bytes.NewReader(archive),
		BundleSize: int64(len(archive)),
	})
	require.NoError(t, err)
	assert.Equal(t, report.ResultCompleteValid, r.Result)

	r, err = anchored(t, p).Verify(t.Context(), verifier.Input{
		Certificate: bytes.NewReader(p.Certificate),
		Sources:     sourcesFor(p.Files),
	})
	require.NoError(t, err)
	assert.Equal(t, report.ResultCompleteValid, r.Result)
}

func TestVerifyReportsUnreadableSource(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	broken := verifier.Source{
		Name:     p.Files[0].Name,
		Explicit: true,
		Open:     func() (io.ReadCloser, error) { return nil, errors.New("permission denied") },
	}

	r, err := offline().VerifyCertificate(t.Context(),
		bytes.NewReader(p.Certificate), []verifier.Source{broken})
	require.NoError(t, err)

	assert.Equal(t, report.StatusSkipped, statusOf(t, r, "sources.item.0"))

	c, _ := r.Check("sources.item.0")
	assert.Contains(t, c.Message, "permission denied")
}

func TestProgressCallback(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(2)})

	var stages []string

	v := verifier.New(verifier.WithOffline(), verifier.WithProgress(func(pr verifier.Progress) {
		stages = append(stages, pr.Stage)
	}))

	_, err := v.VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), sourcesFor(p.Files))
	require.NoError(t, err)

	assert.Contains(t, stages, verifier.StageCertificate)
	assert.Contains(t, stages, verifier.StageSources)
	assert.Contains(t, stages, verifier.StageMerkle)
	assert.Contains(t, stages, verifier.StageTimestamp)
	assert.Contains(t, stages, verifier.StageAccumulator)
	assert.Contains(t, stages, verifier.StageAnchors)
}

func TestTimestampRootsEnableChainValidation(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	t.Run("trusted", func(t *testing.T) {
		t.Parallel()

		v := verifier.New(verifier.WithOffline(), verifier.WithTimestampRoots(p.TSA.RootPool()))

		r, err := v.VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), sourcesFor(p.Files))
		require.NoError(t, err)
		assert.Equal(t, report.StatusValid, statusOf(t, r, "timestamp.trust_chain"))
	})

	t.Run("untrusted", func(t *testing.T) {
		t.Parallel()

		other, err := prooftest.NewTSA()
		require.NoError(t, err)

		v := verifier.New(verifier.WithOffline(), verifier.WithTimestampRoots(other.RootPool()))

		r, err := v.VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), sourcesFor(p.Files))
		require.NoError(t, err)
		assert.Equal(t, report.StatusInvalid, statusOf(t, r, "timestamp.trust_chain"))
		assert.Equal(t, report.ResultInvalid, r.Result)
	})

	t.Run("none supplied", func(t *testing.T) {
		t.Parallel()

		r, err := offline().VerifyCertificate(t.Context(),
			bytes.NewReader(p.Certificate), sourcesFor(p.Files))
		require.NoError(t, err)

		// With neither trust anchors nor a Trusted List source, the path was not
		// established. That is something the verifier could not determine, not a
		// step it chose not to attempt, and it does keep the run from being
		// complete: claiming otherwise would present an unestablished path as if
		// it were established.
		c, ok := r.Check("timestamp.trust_chain")
		require.True(t, ok)
		assert.Equal(t, report.StatusIndeterminate, c.Status)
		assert.NotEmpty(t, c.Message)
		assert.NotEqual(t, report.ResultCompleteValid, r.Result)
	})
}

// TestAnchorStage covers how each provider outcome is reported. The rule is that
// a transaction that contradicts the proof fails the check, while a network that
// could not be reached only skips it: an unreachable endpoint must never look
// like a broken proof.
func TestAnchorStage(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})
	id := "anchors." + stubNetwork

	cases := map[string]struct {
		verifier *verifier.Verifier
		status   report.Status
		result   report.Result
		contains string
	}{
		"anchored": {
			verifier: anchored(t, p),
			status:   report.StatusValid,
			result:   report.ResultCompleteValid,
		},
		"wrong payload on chain": {
			verifier: verifier.New(verifier.WithAnchorVerifier(
				stubAnchor{network: stubNetwork, payload: bytes.Repeat([]byte{0x99}, 64)})),
			status:   report.StatusInvalid,
			result:   report.ResultInvalid,
			contains: "does not carry",
		},
		"transaction not found": {
			verifier: verifier.New(verifier.WithAnchorVerifier(
				stubAnchor{network: stubNetwork, err: anchor.ErrTransactionNotFound})),
			status:   report.StatusInvalid,
			result:   report.ResultInvalid,
			contains: "does not know",
		},
		"transaction without payload": {
			verifier: verifier.New(verifier.WithAnchorVerifier(
				stubAnchor{network: stubNetwork, err: anchor.ErrNoPayload})),
			status:   report.StatusInvalid,
			result:   report.ResultInvalid,
			contains: "no anchored payload",
		},
		"endpoint unreachable": {
			verifier: verifier.New(verifier.WithAnchorVerifier(
				stubAnchor{network: stubNetwork, err: errors.New("connection refused")})),
			status:   report.StatusSkipped,
			result:   report.ResultPartialValid,
			contains: "Nothing is implied",
		},
		"no provider for the network": {
			verifier: verifier.New(verifier.WithAnchorRegistry(anchor.Registry{})),
			status:   report.StatusSkipped,
			result:   report.ResultPartialValid,
			contains: "No verifier is available",
		},
		"network disabled": {
			verifier: offline(),
			status:   report.StatusSkipped,
			result:   report.ResultPartialValid,
			contains: "disabled",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r, err := tc.verifier.VerifyCertificate(t.Context(),
				bytes.NewReader(p.Certificate), sourcesFor(p.Files))
			require.NoError(t, err)

			assert.Equal(t, tc.status, statusOf(t, r, id))
			assert.Equal(t, tc.result, r.Result)

			if tc.contains != "" {
				c, _ := r.Check(id)
				assert.Contains(t, c.Message, tc.contains)
			}
		})
	}
}

// TestAnchorBlockMismatchIsReportedAsContext records that a block reference that
// disagrees with the network is contextual information, not a verification
// failure: the anchoring evidence is the payload, and the recorded block may
// legitimately be stale.
func TestAnchorBlockMismatchIsReportedAsContext(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{
		Files: prooftest.DefaultFiles(1),
		Anchors: []prooftest.Anchor{{
			Network:       stubNetwork,
			TransactionID: "3DZT62LVBKVIYULEPC3QGNEWVMKZEBHXA2PX7BBYU4TL7ZZI2EQQ",
			BlockNumber:   111,
		}},
	})

	r, err := anchored(t, p).VerifyCertificate(t.Context(),
		bytes.NewReader(p.Certificate), sourcesFor(p.Files))
	require.NoError(t, err)

	c, ok := r.Check("anchors." + stubNetwork)
	require.True(t, ok)
	assert.Equal(t, report.StatusValid, c.Status)
	assert.Contains(t, c.Message, "the manifest records block 111")
	assert.Equal(t, "111", c.Details["declared_block"])
	assert.Equal(t, "64055209", c.Details["observed_block"])
	assert.Equal(t, report.ResultCompleteValid, r.Result)
}

func TestProofWithoutAnchorsIsPartial(t *testing.T) {
	t.Parallel()

	p, err := prooftest.New(prooftest.Options{Files: prooftest.DefaultFiles(1)})
	require.NoError(t, err)

	r, err := verifier.New().VerifyCertificate(t.Context(),
		bytes.NewReader(p.Certificate), sourcesFor(p.Files))
	require.NoError(t, err)

	assert.Equal(t, report.ResultPartialValid, r.Result)
	assert.Equal(t, report.StatusSkipped, statusOf(t, r, "anchors.availability"))
}

func TestVerifierRejectsNilReaders(t *testing.T) {
	t.Parallel()

	v := offline()

	_, err := v.VerifyBundle(t.Context(), nil, 0)
	assert.ErrorIs(t, err, verifier.ErrInvalidInput)

	_, err = v.VerifyCertificate(t.Context(), nil, nil)
	assert.ErrorIs(t, err, verifier.ErrInvalidInput)
}

// TestReportIsDeterministic guards the public contract of the report against
// accidental non determinism such as map iteration order leaking into it.
func TestReportIsDeterministic(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(4)})

	first, err := offline().VerifyCertificate(t.Context(),
		bytes.NewReader(p.Certificate), sourcesFor(p.Files))
	require.NoError(t, err)

	for range 5 {
		again, err := offline().VerifyCertificate(t.Context(),
			bytes.NewReader(p.Certificate), sourcesFor(p.Files))
		require.NoError(t, err)
		require.Equal(t, first, again)
	}
}

func TestPrimitivesAreExposed(t *testing.T) {
	t.Parallel()

	leaves := [][]byte{
		mustHash(t, "a"),
		mustHash(t, "b"),
		mustHash(t, "c"),
	}

	root, err := verifier.ComputeMerkleRoot(leaves)
	require.NoError(t, err)
	require.Len(t, root, 64)

	siblings, generatedRoot, err := verifier.GenerateMerkleProof(leaves, 1)
	require.NoError(t, err)
	assert.Equal(t, root, generatedRoot)

	ok, err := verifier.VerifyMerkleProof(leaves[1], siblings, root)
	require.NoError(t, err)
	assert.True(t, ok)

	recomputed, err := verifier.MerkleRootFromProof(leaves[1], siblings)
	require.NoError(t, err)
	assert.Equal(t, root, recomputed)

	ok, err = verifier.VerifyMerkleProof(leaves[2], siblings, root)
	require.NoError(t, err)
	assert.False(t, ok)
}

func mustHash(t *testing.T, s string) []byte {
	t.Helper()

	sum, err := verifier.HashSource(strings.NewReader(s))
	require.NoError(t, err)

	return sum
}

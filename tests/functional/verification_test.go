// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

// Package functional exercises complete, realistic proof structures through the
// public verifier API.
//
// Every fixture is generated at test time so that tampered variants can be
// produced, and so that the production fixture under testdata is never mutated.
package functional_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
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
	"github.com/sealway-hq/sealway-verifier/packages/verifier/anchor/algorand"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/anchor/evm"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/report"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/trust"
)

const algorandTxID = "3DZT62LVBKVIYULEPC3QGNEWVMKZEBHXA2PX7BBYU4TL7ZZI2EQQ"

const polygonTxID = "0x937321db55b20eab05656eb1267a353f24fd914b088d446df0d82a32af6646d5"

func anchors() []prooftest.Anchor {
	return []prooftest.Anchor{
		{Network: algorand.Network, TransactionID: algorandTxID, BlockNumber: 64055209},
		{Network: evm.NetworkPolygon, TransactionID: polygonTxID, BlockNumber: 91994197},
	}
}

func newProof(t *testing.T, opts prooftest.Options) *prooftest.Proof {
	t.Helper()

	if opts.Anchors == nil {
		opts.Anchors = anchors()
	}

	if opts.Files == nil {
		opts.Files = prooftest.DefaultFiles(3)
	}

	// A complete proof carries its revocation evidence; a test wanting the
	// opposite builds it without.
	if opts.Revocation == nil {
		opts.Revocation = &prooftest.RevocationOptions{Status: ocsp.Good}
	}

	p, err := prooftest.New(opts)
	require.NoError(t, err)

	return p
}

// chainServer serves both a public indexer and a JSON-RPC node from one
// httptest server, so the whole anchoring stage runs against real provider code
// without touching a live network.
func chainServer(t *testing.T, payload []byte) (algorandEndpoint, evmEndpoint string) {
	t.Helper()

	note := base64Std(payload)
	input := "0x" + hexOf(payload)

	mux := http.NewServeMux()
	mux.HandleFunc("/algorand/v2/transactions/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"transaction":{"id":"`+algorandTxID+
			`","note":"`+note+`","tx-type":"pay","confirmed-round":64055209}}`)
	})
	mux.HandleFunc("/evm", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"hash":"`+polygonTxID+
			`","input":"`+input+`","blockNumber":"0x57bb855","blockHash":"0x987b"}}`)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return srv.URL + "/algorand", srv.URL + "/evm"
}

// online returns a verifier whose anchor providers point at a local test server
// serving the given anchored payload.
func online(t *testing.T, p *prooftest.Proof, payload []byte) *verifier.Verifier {
	t.Helper()

	algorandEndpoint, evmEndpoint := chainServer(t, payload)
	provider, signer := trustFor(t, p)

	return verifier.New(
		verifier.WithAnchorEndpoint(algorand.Network, algorandEndpoint),
		verifier.WithAnchorEndpoint(evm.NetworkPolygon, evmEndpoint),
		verifier.WithTrustProvider(provider),
		verifier.WithTrustListSigners(signer),
	)
}

// trustFor builds a Trusted List recognising the throwaway authority that signed
// the timestamp of p, so that a complete verification is reachable without
// touching the real European publications.
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

func offline() *verifier.Verifier { return verifier.New(verifier.WithOffline()) }

func sourcesFor(files []prooftest.File) []verifier.Source {
	out := make([]verifier.Source, 0, len(files))

	for _, f := range files {
		out = append(out, verifier.Source{
			Name:     f.Name,
			Size:     int64(len(f.Content)),
			Explicit: true,
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(f.Content)), nil
			},
		})
	}

	return out
}

func verifyBundle(t *testing.T, v *verifier.Verifier, p *prooftest.Proof,
	opts prooftest.BundleOptions,
) (*report.Report, error) {
	t.Helper()

	archive, err := p.Bundle(opts)
	require.NoError(t, err)

	return v.VerifyBundle(context.Background(), bytes.NewReader(archive), int64(len(archive)))
}

func statusOf(t *testing.T, r *report.Report, id string) report.Status {
	t.Helper()

	c, ok := r.Check(id)
	require.True(t, ok, "check %q is missing", id)

	return c.Status
}

// TestBundleCompleteVerification is the headline case: a bundle carries
// everything, so every stage runs and nothing is skipped for lack of evidence.
func TestBundleCompleteVerification(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{})

	r, err := verifyBundle(t, online(t, p, p.AccumulatorRoot), p, prooftest.BundleOptions{})
	require.NoError(t, err)

	assert.Equal(t, report.ResultCompleteValid, r.Result)
	assert.Zero(t, r.Summary.Invalid)
	assert.Zero(t, r.Summary.SkippedAffectingCompleteness)

	for _, id := range []string{
		"certificate.container",
		"certificate.manifest",
		"certificate.manifest_schema",
		"certificate.timestamp_token",
		"certificate.loose_copies",
		"sources.availability",
		"sources.item.0",
		"sources.item.1",
		"sources.item.2",
		"proof_merkle.leaf_hashes",
		"proof_merkle.root",
		"proof_merkle.certified_root",
		"proof_merkle.item_proofs",
		"timestamp.structure",
		"timestamp.signature",
		"timestamp.signer_usage",
		"timestamp.imprint",
		"timestamp.metadata",
		"accumulator.inclusion_proof",
		"accumulator.root",
		"anchors.algorand",
		"anchors.polygon",
	} {
		assert.Equal(t, report.StatusValid, statusOf(t, r, id), "check %s", id)
	}
}

func TestCertificateWithSourcesCompleteVerification(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{})

	r, err := online(t, p, p.AccumulatorRoot).VerifyCertificate(context.Background(),
		bytes.NewReader(p.Certificate), sourcesFor(p.Files))
	require.NoError(t, err)

	assert.Equal(t, report.ResultCompleteValid, r.Result)
	assert.Equal(t, report.StatusValid, statusOf(t, r, "proof_merkle.root"))
}

func TestCertificateOnlyPartialVerification(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{})

	r, err := online(t, p, p.AccumulatorRoot).VerifyCertificate(context.Background(),
		bytes.NewReader(p.Certificate), nil)
	require.NoError(t, err)

	assert.Equal(t, report.ResultPartialValid, r.Result)
	assert.Zero(t, r.Summary.Invalid)

	// Nothing that needs the files is claimed.
	assert.Equal(t, report.StatusSkipped, statusOf(t, r, "sources.availability"))
	assert.Equal(t, report.StatusSkipped, statusOf(t, r, "proof_merkle.root"))

	// Everything that does not is still established.
	assert.Equal(t, report.StatusValid, statusOf(t, r, "timestamp.imprint"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "accumulator.root"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "anchors.algorand"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "anchors.polygon"))
}

func TestOfflineVerificationIsPartialButComplete(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{})

	r, err := verifyBundle(t, offline(), p, prooftest.BundleOptions{})
	require.NoError(t, err)

	assert.Equal(t, report.ResultPartialValid, r.Result)
	assert.Zero(t, r.Summary.Invalid,
		"disabling the network must never make a local verification fail")

	// Every local cryptographic step is still performed.
	assert.Equal(t, report.StatusValid, statusOf(t, r, "proof_merkle.root"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "timestamp.imprint"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "accumulator.root"))

	// Only the anchors are skipped, with a reason.
	for _, id := range []string{"anchors.algorand", "anchors.polygon"} {
		c, ok := r.Check(id)
		require.True(t, ok)
		assert.Equal(t, report.StatusSkipped, c.Status)
		assert.Contains(t, c.Message, "disabled")
	}
}

func TestWrongSourceIsInvalid(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(2)})

	sources := sourcesFor(p.Files)
	sources[1] = verifier.Source{
		Name:     p.Files[1].Name,
		Explicit: true,
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("tampered content")), nil
		},
	}

	r, err := offline().VerifyCertificate(context.Background(),
		bytes.NewReader(p.Certificate), sources)
	require.NoError(t, err)

	assert.Equal(t, report.ResultInvalid, r.Result)
	assert.Equal(t, report.StatusValid, statusOf(t, r, "sources.item.0"))
	assert.Equal(t, report.StatusInvalid, statusOf(t, r, "sources.item.1"))
}

// TestTamperedFixtures walks the ways a proof can be broken and checks each one
// is caught, and caught by the step it belongs to.
func TestTamperedFixtures(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		options prooftest.Options
		bundle  prooftest.BundleOptions
		check   string
	}{
		"modified manifest leaf": {
			options: prooftest.Options{
				MutateManifest: func(m map[string]any) {
					item := m["items"].([]any)[0].(map[string]any)
					item["leaf_hash"] = strings.Repeat("ab", 64)
					item["hash_sha512"] = strings.Repeat("ab", 64)
				},
			},
			check: "proof_merkle.certified_root",
		},
		"modified proof root": {
			options: prooftest.Options{
				MutateManifest: func(m map[string]any) {
					root := strings.Repeat("cd", 64)
					m["proof"].(map[string]any)["merkle_root"] = root
					m["notarization"].(map[string]any)["merkle_root"] = root
					m["notarization"].(map[string]any)["hash"] = root
				},
			},
			check: "proof_merkle.root",
		},
		"modified accumulator root": {
			options: prooftest.Options{
				MutateManifest: func(m map[string]any) {
					m["notarization"].(map[string]any)["accumulator_root"] = strings.Repeat("ef", 64)
				},
			},
			check: "accumulator.root",
		},
		"modified inclusion path": {
			options: prooftest.Options{
				MutateManifest: func(m map[string]any) {
					p := m["notarization"].(map[string]any)["inclusion_proof"].(map[string]any)
					p["siblings"].([]any)[0].(map[string]any)["hash"] = strings.Repeat("11", 64)
				},
			},
			check: "accumulator.inclusion_proof",
		},
		"modified item inclusion path direction": {
			options: prooftest.Options{
				Files: prooftest.DefaultFiles(4),
				MutateManifest: func(m map[string]any) {
					item := m["items"].([]any)[1].(map[string]any)
					p := item["merkle_proof"].(map[string]any)
					p["siblings"].([]any)[0].(map[string]any)["position"] = "right"
				},
			},
			check: "proof_merkle.item_proofs",
		},
		"modified timestamp imprint": {
			options: prooftest.Options{
				TokenOptions: &prooftest.TokenOptions{Imprint: bytes.Repeat([]byte{0x42}, 64)},
			},
			check: "timestamp.imprint",
		},
		"modified timestamp signature": {
			options: prooftest.Options{
				TokenOptions: &prooftest.TokenOptions{CorruptSignature: true},
			},
			check: "timestamp.signature",
		},
		"loose copy contradicts the certificate": {
			options: prooftest.Options{},
			bundle: prooftest.BundleOptions{
				LooseManifest: []byte(`{"version":"1.1","proof":{"public_id":"SW-2026-FORGED0"}}`),
			},
			check: "certificate.loose_copies",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			p := newProof(t, tc.options)

			r, err := verifyBundle(t, offline(), p, tc.bundle)
			require.NoError(t, err)

			assert.Equal(t, report.ResultInvalid, r.Result)
			assert.Equal(t, report.StatusInvalid, statusOf(t, r, tc.check))
		})
	}
}

// TestAnchorPayloadMustCarryTheRoot is the property that makes an anchor
// evidence rather than trivia: a transaction that exists but carries something
// else fails.
func TestAnchorPayloadMustCarryTheRoot(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{})

	r, err := verifyBundle(t, online(t, p, bytes.Repeat([]byte{0x99}, 64)), p, prooftest.BundleOptions{})
	require.NoError(t, err)

	assert.Equal(t, report.ResultInvalid, r.Result)
	assert.Equal(t, report.StatusInvalid, statusOf(t, r, "anchors.algorand"))
	assert.Equal(t, report.StatusInvalid, statusOf(t, r, "anchors.polygon"))
}

// TestUnreachableNetworkOnlySkips separates a broken proof from a broken
// network.
func TestUnreachableNetworkOnlySkips(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{})

	v := verifier.New(
		verifier.WithAnchorEndpoint(algorand.Network, "http://127.0.0.1:1"),
		verifier.WithAnchorEndpoint(evm.NetworkPolygon, "http://127.0.0.1:1"),
		verifier.WithNetworkTimeout(500*time.Millisecond),
	)

	r, err := verifyBundle(t, v, p, prooftest.BundleOptions{})
	require.NoError(t, err)

	assert.Equal(t, report.ResultPartialValid, r.Result)
	assert.Zero(t, r.Summary.Invalid)
	assert.Equal(t, report.StatusSkipped, statusOf(t, r, "anchors.algorand"))
}

func TestUnsupportedAnchorNetworkSkips(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{
		Anchors: []prooftest.Anchor{{Network: "unknownchain", TransactionID: "TX"}},
	})

	r, err := verifyBundle(t, verifier.New(), p, prooftest.BundleOptions{})
	require.NoError(t, err)

	assert.Equal(t, report.ResultPartialValid, r.Result)

	c, ok := r.Check("anchors.unknownchain")
	require.True(t, ok)
	assert.Equal(t, report.StatusSkipped, c.Status)
	assert.Contains(t, c.Message, "No verifier is available")
}

func TestLargeProof(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(33)})

	r, err := verifyBundle(t, offline(), p, prooftest.BundleOptions{})
	require.NoError(t, err)

	assert.Zero(t, r.Summary.Invalid)
	assert.Equal(t, report.StatusValid, statusOf(t, r, "proof_merkle.root"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "proof_merkle.item_proofs"))

	require.NotNil(t, r.Certificate)
	assert.Equal(t, 33, r.Certificate.ItemCount)
}

// TestSingleItemProof covers the tree shape most likely to be got wrong: a one
// leaf tree still duplicates its leaf.
func TestSingleItemProof(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	r, err := verifyBundle(t, offline(), p, prooftest.BundleOptions{})
	require.NoError(t, err)

	assert.Zero(t, r.Summary.Invalid)
	assert.Equal(t, report.StatusValid, statusOf(t, r, "proof_merkle.root"))
}

func TestHostileBundlesAreRefused(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	cases := map[string]prooftest.BundleOptions{
		"zip slip":               {ExtraEntries: map[string][]byte{"../../escaped": []byte("x")}},
		"absolute path":          {ExtraEntries: map[string][]byte{"/etc/passwd": []byte("x")}},
		"backslash traversal":    {ExtraEntries: map[string][]byte{`..\..\escaped`: []byte("x")}},
		"missing certificate":    {OmitCertificate: true},
		"ambiguous certificates": {ExtraCertificates: 1},
	}

	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := verifyBundle(t, offline(), p, opts)
			assert.Error(t, err, "a hostile or unusable archive must be an operational error")
		})
	}
}

func TestReportIsSerializableAndStable(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{})

	first, err := verifyBundle(t, offline(), p, prooftest.BundleOptions{})
	require.NoError(t, err)

	second, err := verifyBundle(t, offline(), p, prooftest.BundleOptions{})
	require.NoError(t, err)

	assert.Equal(t, first, second)

	for _, c := range first.Checks() {
		assert.NotEmpty(t, c.ID)
		assert.NotEmpty(t, c.Title)
		assert.NotEmpty(t, c.Message, "check %s carries no explanation", c.ID)
		assert.Contains(t,
			[]report.Status{
				report.StatusValid,
				report.StatusInvalid,
				report.StatusSkipped,
				report.StatusIndeterminate,
			},
			c.Status)
	}
}

func base64Std(data []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	var out strings.Builder

	for i := 0; i < len(data); i += 3 {
		var chunk [3]byte

		n := copy(chunk[:], data[i:])
		v := uint32(chunk[0])<<16 | uint32(chunk[1])<<8 | uint32(chunk[2])

		out.WriteByte(alphabet[v>>18&0x3f])
		out.WriteByte(alphabet[v>>12&0x3f])

		if n > 1 {
			out.WriteByte(alphabet[v>>6&0x3f])
		} else {
			out.WriteByte('=')
		}

		if n > 2 {
			out.WriteByte(alphabet[v&0x3f])
		} else {
			out.WriteByte('=')
		}
	}

	return out.String()
}

func hexOf(data []byte) string {
	const digits = "0123456789abcdef"

	out := make([]byte, 0, len(data)*2)
	for _, b := range data {
		out = append(out, digits[b>>4], digits[b&0x0f])
	}

	return string(out)
}

// The built-in providers must keep satisfying the public provider interface, so
// a third party implementation stays a drop-in replacement.
var (
	_ anchor.Verifier = (*evm.Verifier)(nil)
	_ anchor.Verifier = (*algorand.Verifier)(nil)
)

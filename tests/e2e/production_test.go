// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

// Package e2e verifies the real production proof bundle checked into testdata.
//
// These tests are the ones that would notice if the verifier and the issuer ever
// drifted apart. They never mutate the fixture, and they never require a live
// public network: the blockchain anchors are served from recorded responses, and
// an opt-in test verifies them against the real networks when explicitly asked
// for.
package e2e_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/unicode/norm"

	"github.com/sealway-hq/sealway-verifier/packages/verifier"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/anchor/algorand"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/anchor/evm"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/proof"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/report"
)

// Facts about the production fixture. They are asserted rather than derived so
// that a change in the public format is noticed rather than absorbed.
const (
	fixtureName   = "sealway-proof-SW-2026-D8DY92C8.zip"
	fixturePublic = "SW-2026-D8DY92C8"

	// The production fixture stores the certified file name in Unicode NFD, the
	// decomposed form macOS filesystems use. Source matching normalizes names to
	// NFC before comparing them, so the same file verifies whichever form the
	// caller's filesystem produces.
	fixtureSourceName = "Discours de Steve Jobs \u00e0 Stanford.pdf"

	fixtureSourceSHA512 = "c1d9c27cb49dd2c3ac19560b3d9dea3b83bd63121fda2ecb385264a20b958d85" +
		"d67615cab0c8db07839e559af869c9a03a019da74004f3315e26aec41036ca3f"
	fixtureMerkleRoot = "e17aeb282703de68c5b455083e08281d01683eb302d0af92708c0ce2f30165e9" +
		"e52bff2c99f6f47ff7af98ab8aea84fed7cdb3bd67c343d4f4c43dbce829088c"
	fixtureAccumulatorRoot = "da0ad24a38076ce921ccd08db6810a77ad3dcdaf74fbcc63bc4dfe70495c4ffa" +
		"957bc53f8e68752c52b8d8dd51598b0997663569ba517953d08c8a8062ac3e2c"

	fixtureAlgorandTx = "3DZT62LVBKVIYULEPC3QGNEWVMKZEBHXA2PX7BBYU4TL7ZZI2EQQ"
	fixturePolygonTx  = "0x937321db55b20eab05656eb1267a353f24fd914b088d446df0d82a32af6646d5"
	fixtureBaseTx     = "0x309cc5cd84041915d824f83281f19f3ba747c73a3ddc96eb7261dbd06a89044d"
)

// LiveTestsEnv opts into verifying the anchors against the real public networks.
const LiveTestsEnv = "SEALWAY_VERIFIER_LIVE_TESTS"

func fixturePath(t *testing.T) string {
	t.Helper()

	path := filepath.Join("..", "..", "testdata", fixtureName)

	if _, err := os.Stat(path); err != nil {
		t.Skipf("the production fixture is not available: %v", err)
	}

	return path
}

func fixtureBytes(t *testing.T) []byte {
	t.Helper()

	data, err := os.ReadFile(fixturePath(t))
	require.NoError(t, err)

	return data
}

// extract reads one entry out of the fixture archive without writing anything to
// disk, so the fixture itself is never touched.
func extract(t *testing.T, prefix, suffix string) (name string, data []byte) {
	t.Helper()

	archive := fixtureBytes(t)

	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	require.NoError(t, err)

	for _, f := range zr.File {
		if !strings.HasPrefix(f.Name, prefix) || !strings.HasSuffix(f.Name, suffix) {
			continue
		}

		rc, err := f.Open()
		require.NoError(t, err)

		content, err := io.ReadAll(rc)
		require.NoError(t, rc.Close())
		require.NoError(t, err)

		return f.Name, content
	}

	t.Fatalf("no entry matching %q..%q in the fixture", prefix, suffix)

	return "", nil
}

func certificate(t *testing.T) []byte {
	t.Helper()

	_, data := extract(t, "sealway-certificate-", ".pdf")

	return data
}

func sourceFile(t *testing.T) []byte {
	t.Helper()

	_, data := extract(t, "files/", ".pdf")

	return data
}

// recordedChain serves the anchor lookups from responses recorded against the
// real public networks, so the default test run never depends on their
// availability.
func recordedChain(t *testing.T) []verifier.Option {
	t.Helper()

	root, err := hex.DecodeString(fixtureAccumulatorRoot)
	require.NoError(t, err)

	note := base64.StdEncoding.EncodeToString(root)

	mux := http.NewServeMux()
	mux.HandleFunc("/algorand/v2/transactions/"+fixtureAlgorandTx,
		func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"current-round":1,"transaction":{"id":"`+fixtureAlgorandTx+
				`","tx-type":"pay","confirmed-round":64055209,"note":"`+note+`"}}`)
		})

	evmHandler := func(blockNumber string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)

			var req struct {
				Method string   `json:"method"`
				Params []string `json:"params"`
			}

			_ = json.Unmarshal(body, &req)

			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"hash":"`+req.Params[0]+
				`","input":"0x`+fixtureAccumulatorRoot+`","blockNumber":"`+blockNumber+
				`","blockHash":"0x987bd1e7"}}`)
		}
	}

	mux.HandleFunc("/polygon", evmHandler("0x57bb855"))
	mux.HandleFunc("/base", evmHandler("0x2fa3ad1"))

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return []verifier.Option{
		verifier.WithAnchorEndpoint(algorand.Network, srv.URL+"/algorand"),
		verifier.WithAnchorEndpoint(evm.NetworkPolygon, srv.URL+"/polygon"),
		verifier.WithAnchorEndpoint(evm.NetworkBase, srv.URL+"/base"),
	}
}

func statusOf(t *testing.T, r *report.Report, id string) report.Status {
	t.Helper()

	c, ok := r.Check(id)
	require.True(t, ok, "check %q is missing from the report", id)

	return c.Status
}

// TestProductionBundleVerifiesCompletely is the end-to-end guarantee: the real
// bundle verifies from the original file all the way to the public anchors.
func TestProductionBundleVerifiesCompletely(t *testing.T) {
	t.Parallel()

	archive := fixtureBytes(t)

	v := verifier.New(recordedChain(t)...)

	r, err := v.VerifyBundle(context.Background(), bytes.NewReader(archive), int64(len(archive)))
	require.NoError(t, err)

	assert.Equal(t, report.ResultCompleteValid, r.Result)
	assert.Zero(t, r.Summary.Invalid)

	require.NotNil(t, r.Certificate)
	assert.Equal(t, fixturePublic, r.Certificate.PublicID)
	assert.Equal(t, 1, r.Certificate.ItemCount)
	assert.Equal(t, fixtureMerkleRoot, r.Certificate.MerkleRoot)
	assert.Equal(t, fixtureAccumulatorRoot, r.Certificate.AccumulatorRoot)

	// The whole chain of evidence, one step at a time.
	for _, id := range []string{
		"certificate.container",
		"certificate.manifest",
		"certificate.manifest_schema",
		"certificate.timestamp_token",
		"certificate.loose_copies",
		"sources.availability",
		"sources.item.0",
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
		"anchors.base",
	} {
		assert.Equal(t, report.StatusValid, statusOf(t, r, id), "check %s", id)
	}

	// Nothing is claimed about trust or eIDAS qualification.
	for _, id := range []string{"timestamp.trust_chain", "timestamp.qualified", "certificate.signature"} {
		c, ok := r.Check(id)
		require.True(t, ok)
		assert.Equal(t, report.StatusSkipped, c.Status)
		assert.False(t, c.AffectsCompleteness)
	}
}

// TestProductionProofIsInternallyCorrect asserts the public cryptographic
// profile on the real fixture:
//
//	source SHA-512 -> proof Merkle root -> accumulator inclusion -> RFC 3161 imprint
func TestProductionProofIsInternallyCorrect(t *testing.T) {
	t.Parallel()

	source := sourceFile(t)

	sum, err := verifier.HashSource(bytes.NewReader(source))
	require.NoError(t, err)
	assert.Equal(t, fixtureSourceSHA512, hex.EncodeToString(sum),
		"the proof integrity hash is the SHA-512 of the raw file bytes")

	// The single leaf tree still duplicates its leaf.
	root, err := verifier.ComputeMerkleRoot([][]byte{sum})
	require.NoError(t, err)
	assert.Equal(t, fixtureMerkleRoot, hex.EncodeToString(root))

	// The accumulator holds the proof root as its single leaf.
	accumulator, err := verifier.ComputeMerkleRoot([][]byte{root})
	require.NoError(t, err)
	assert.Equal(t, fixtureAccumulatorRoot, hex.EncodeToString(accumulator))
}

func TestProductionManifestMatchesTheDeclaredFormat(t *testing.T) {
	t.Parallel()

	_, data := extract(t, "sealway-proof.json", "")

	m, err := proof.ParseBytes(data)
	require.NoError(t, err)
	require.NoError(t, m.Validate())

	assert.Equal(t, fixturePublic, m.Proof.PublicID)
	assert.Equal(t, "SHA-512", m.Proof.HashAlgorithm)
	assert.Equal(t, fixtureMerkleRoot, m.Proof.MerkleRoot.String())
	assert.Equal(t, fixtureAccumulatorRoot, m.Notarization.AccumulatorRoot.String())

	require.Len(t, m.Items, 1)
	assert.Equal(t, fixtureSourceName, norm.NFC.String(m.Items[0].Filename))
	assert.NotEqual(t, fixtureSourceName, m.Items[0].Filename,
		"the fixture is expected to carry the decomposed form of the name")
	assert.Equal(t, fixtureSourceSHA512, m.Items[0].LeafHash.String())
	assert.True(t, m.Items[0].LeafHash.Equal(m.Items[0].HashSHA512))

	networks := make([]string, 0, len(m.Anchors()))
	for _, a := range m.Anchors() {
		networks = append(networks, a.ProviderName)
	}

	assert.ElementsMatch(t, []string{"algorand", "polygon", "base"}, networks)
}

func TestProductionCertificateAloneIsPartial(t *testing.T) {
	t.Parallel()

	v := verifier.New(recordedChain(t)...)

	r, err := v.VerifyCertificate(context.Background(), bytes.NewReader(certificate(t)), nil)
	require.NoError(t, err)

	assert.Equal(t, report.ResultPartialValid, r.Result)
	assert.Zero(t, r.Summary.Invalid)

	assert.Equal(t, report.StatusSkipped, statusOf(t, r, "sources.availability"))
	assert.Equal(t, report.StatusSkipped, statusOf(t, r, "proof_merkle.root"))

	assert.Equal(t, report.StatusValid, statusOf(t, r, "proof_merkle.certified_root"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "timestamp.imprint"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "accumulator.root"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "anchors.algorand"))
}

func TestProductionCertificateWithSourceIsComplete(t *testing.T) {
	t.Parallel()

	content := sourceFile(t)

	src := verifier.Source{
		Name:     fixtureSourceName,
		Size:     int64(len(content)),
		Explicit: true,
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(content)), nil
		},
	}

	v := verifier.New(recordedChain(t)...)

	r, err := v.VerifyCertificate(context.Background(),
		bytes.NewReader(certificate(t)), []verifier.Source{src})
	require.NoError(t, err)

	assert.Equal(t, report.ResultCompleteValid, r.Result)
	assert.Equal(t, report.StatusValid, statusOf(t, r, "sources.item.0"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "proof_merkle.root"))
}

func TestProductionCertificateWithWrongSourceIsInvalid(t *testing.T) {
	t.Parallel()

	src := verifier.Source{
		Name:     fixtureSourceName,
		Explicit: true,
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("not the certified content")), nil
		},
	}

	v := verifier.New(verifier.WithOffline())

	r, err := v.VerifyCertificate(context.Background(),
		bytes.NewReader(certificate(t)), []verifier.Source{src})
	require.NoError(t, err)

	assert.Equal(t, report.ResultInvalid, r.Result)
	assert.Equal(t, report.StatusInvalid, statusOf(t, r, "sources.item.0"))
}

func TestProductionBundleOffline(t *testing.T) {
	t.Parallel()

	archive := fixtureBytes(t)

	r, err := verifier.New(verifier.WithOffline()).
		VerifyBundle(context.Background(), bytes.NewReader(archive), int64(len(archive)))
	require.NoError(t, err)

	assert.Equal(t, report.ResultPartialValid, r.Result)
	assert.Zero(t, r.Summary.Invalid)
	assert.Equal(t, report.StatusValid, statusOf(t, r, "proof_merkle.root"))
	assert.Equal(t, report.StatusSkipped, statusOf(t, r, "anchors.algorand"))
}

// TestProductionLooseCopiesAreConsistent records that the convenience copies of
// the fixture agree with the certificate on everything cryptographic, even
// though they are not byte identical: they were regenerated moments apart, which
// is exactly why they cannot be authoritative.
func TestProductionLooseCopiesAreConsistent(t *testing.T) {
	t.Parallel()

	archive := fixtureBytes(t)

	r, err := verifier.New(verifier.WithOffline()).
		VerifyBundle(context.Background(), bytes.NewReader(archive), int64(len(archive)))
	require.NoError(t, err)

	c, ok := r.Check("certificate.loose_copies")
	require.True(t, ok)
	assert.Equal(t, report.StatusValid, c.Status)
}

// TestProductionAnchorsAgainstLiveNetworks verifies the fixture against the real
// public networks. It is opt-in so that ordinary runs never depend on third
// party availability.
func TestProductionAnchorsAgainstLiveNetworks(t *testing.T) {
	if os.Getenv(LiveTestsEnv) == "" {
		t.Skipf("set %s=1 to verify the anchors against the live public networks", LiveTestsEnv)
	}

	archive := fixtureBytes(t)

	v := verifier.New(verifier.WithNetworkTimeout(30 * time.Second))

	r, err := v.VerifyBundle(context.Background(), bytes.NewReader(archive), int64(len(archive)))
	require.NoError(t, err)

	for _, id := range []string{"anchors.algorand", "anchors.polygon", "anchors.base"} {
		c, ok := r.Check(id)
		require.True(t, ok)
		assert.NotEqual(t, report.StatusInvalid, c.Status, "%s: %s", id, c.Message)
	}
}

// TestProductionFixtureIsNotMutated is a guard on the test suite itself: the
// checked-in fixture must be byte identical before and after the whole run.
func TestProductionFixtureIsNotMutated(t *testing.T) {
	before, err := verifier.HashSource(bytes.NewReader(fixtureBytes(t)))
	require.NoError(t, err)

	archive := fixtureBytes(t)

	_, err = verifier.New(verifier.WithOffline()).
		VerifyBundle(context.Background(), bytes.NewReader(archive), int64(len(archive)))
	require.NoError(t, err)

	after, err := verifier.HashSource(bytes.NewReader(fixtureBytes(t)))
	require.NoError(t, err)

	assert.Equal(t, before, after)
}

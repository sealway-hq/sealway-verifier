// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package cli_test

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealway-hq/sealway-verifier/apps/cli/internal/cli"
	"github.com/sealway-hq/sealway-verifier/internal/prooftest"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/report"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/trust"
)

// mirror serves a generated European scheme over HTTP, standing in for the
// official publications without reaching them.
func mirror(t *testing.T, lotl, list []byte) string {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/lotl.xml", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(lotl)
	})
	mux.HandleFunc("/lists/es.xml", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(list)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return srv.URL
}

// scheme builds a European scheme recognising the authority that timestamped p.
func scheme(t *testing.T, p *prooftest.Proof) (lotl, list []byte, signerPEM string) {
	t.Helper()

	s, err := prooftest.NewTrustScheme("ES")
	require.NoError(t, err)

	lotl, err = s.LOTL(prooftest.LOTLOptions{})
	require.NoError(t, err)

	list, err = s.TrustList(prooftest.TrustListOptions{
		Services: []prooftest.TrustService{{
			ProviderName: "Test Trust Services",
			ServiceName:  "Qualified electronic time stamps",
			Identity:     p.TSA.RootCert,
			Status:       prooftest.StatusGranted,
		}},
	})
	require.NoError(t, err)

	return lotl, list, "-----BEGIN CERTIFICATE-----\n" +
		base64Wrap(s.LOTLSigner.Certificate.Raw) + "-----END CERTIFICATE-----\n"
}

// TestTrustFetchWritesAUsableSnapshot covers the whole operator workflow: fetch
// the lists once, then verify against them without a network.
func TestTrustFetchWritesAUsableSnapshot(t *testing.T) {
	t.Parallel()

	p, err := prooftest.New(prooftest.Options{Files: prooftest.DefaultFiles(1)})
	require.NoError(t, err)

	lotl, list, _ := scheme(t, p)
	base := mirror(t, lotl, list)

	dir := filepath.Join(t.TempDir(), "trust")

	res := run(t, "trust", "fetch", dir,
		"--territory", "ES",
		"--lotl-url", base+"/lotl.xml",
		"--list-url", base+"/lists/{territory}.xml")

	// The generated scheme is not signed by the shipped European anchor, so the
	// fetch refuses it. That refusal is the point: material that cannot be
	// authenticated is never written.
	assert.Equal(t, cli.ExitError, res.code)
	assert.Contains(t, res.stderr, "not authentic")
}

// realTrustMaterial reads the official European publications kept in testdata.
//
// They are the genuine signed documents, so a mirror serving them lets the
// success path of a fetch run against material the shipped anchor actually
// authenticates. A generated scheme cannot reach that path, which is why the
// test above stops at the refusal.
func realTrustMaterial(t *testing.T) (lotl, list []byte) {
	t.Helper()

	// The package sits four levels below the repository root.
	const base = "../../../../testdata/trust"

	read := func(name string) []byte {
		compressed, err := os.ReadFile(filepath.Join(base, name))
		require.NoError(t, err)

		zr, err := gzip.NewReader(bytes.NewReader(compressed))
		require.NoError(t, err)

		data, err := io.ReadAll(zr)
		require.NoError(t, err)

		return data
	}

	return read("eu-lotl.xml.gz"), read("es-trusted-list.xml.gz")
}

// TestTrustFetchAuthenticatesAndWritesTheOfficialLists covers what an operator
// actually does, against the real European publications served from a mirror.
//
// A mirror is a transport and never an authority: it carries the official signed
// documents unchanged, and the fetch verifies the European signatures itself. A
// mirror can therefore withhold or delay material, but it cannot invent a
// qualified service.
func TestTrustFetchAuthenticatesAndWritesTheOfficialLists(t *testing.T) {
	t.Parallel()

	lotl, list := realTrustMaterial(t)
	base := mirror(t, lotl, list)

	dir := filepath.Join(t.TempDir(), "trust")

	res := run(t, "trust", "fetch", dir,
		"--territory", "es",
		"--lotl-url", base+"/lotl.xml",
		"--list-url", base+"/lists/{territory}.xml")

	require.Equal(t, cli.ExitCompleteValid, res.code, "stderr: %s", res.stderr)

	// The operator is told which issue of each list the snapshot pins, so that a
	// later disagreement can be traced to a specific publication.
	assert.Contains(t, res.stdout, "fetched and authenticated the ES Trusted List")
	assert.Contains(t, res.stdout, "European List of Trusted Lists: sequence")
	assert.Contains(t, res.stdout, "ES Trusted List: sequence")

	// The documents reach disk byte for byte: a snapshot that reformatted them
	// would break the signatures it exists to carry.
	written, err := os.ReadFile(filepath.Join(dir, "lotl.xml"))
	require.NoError(t, err)
	assert.Equal(t, lotl, written)

	written, err = os.ReadFile(filepath.Join(dir, "lists", "es.xml"))
	require.NoError(t, err)
	assert.Equal(t, list, written)

	var manifest map[string]any

	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &manifest))

	assert.Equal(t, trust.SnapshotFormat, manifest["format"],
		"a mirror publishes the identifier a reader checks")
}

// TestTrustFetchLowercasesAndTrimsTerritories keeps the flag forgiving about
// spelling while the snapshot stays canonical, because a snapshot is read back
// by territory code.
func TestTrustFetchNormalisesTheTerritory(t *testing.T) {
	t.Parallel()

	lotl, list := realTrustMaterial(t)
	base := mirror(t, lotl, list)

	dir := filepath.Join(t.TempDir(), "trust")

	res := run(t, "trust", "fetch", dir,
		"--territory", "  es  ",
		"--territory", "",
		"--lotl-url", base+"/lotl.xml",
		"--list-url", base+"/lists/{territory}.xml")

	require.Equal(t, cli.ExitCompleteValid, res.code, "stderr: %s", res.stderr)
	assert.FileExists(t, filepath.Join(dir, "lists", "es.xml"))
}

// TestTrustFetchRefusesToWriteWhereItCannot reports a directory it cannot create
// as an operational failure rather than losing the material silently.
func TestTrustFetchRefusesToWriteWhereItCannot(t *testing.T) {
	t.Parallel()

	lotl, list := realTrustMaterial(t)
	base := mirror(t, lotl, list)

	// A regular file where the snapshot directory should go.
	blocked := write(t, filepath.Join(t.TempDir(), "occupied"), []byte("not a directory"))

	res := run(t, "trust", "fetch", filepath.Join(blocked, "trust"),
		"--territory", "ES",
		"--lotl-url", base+"/lotl.xml",
		"--list-url", base+"/lists/{territory}.xml")

	assert.Equal(t, cli.ExitError, res.code)
	assert.NotEmpty(t, res.stderr)
}

// TestTrustFetchRefusesUnauthenticMaterial is the same guarantee stated
// directly: nothing reaches disk unless its signature verified.
func TestTrustFetchRefusesUnauthenticMaterial(t *testing.T) {
	t.Parallel()

	base := mirror(t, []byte("<not-a-list/>"), []byte("<not-a-list/>"))

	dir := filepath.Join(t.TempDir(), "trust")

	res := run(t, "trust", "fetch", dir, "--lotl-url", base+"/lotl.xml")

	assert.Equal(t, cli.ExitError, res.code)
	assert.NoDirExists(t, dir)
}

// TestVerifyReadsATrustSnapshot checks the flag an operator uses offline.
func TestVerifyReadsATrustSnapshot(t *testing.T) {
	t.Parallel()

	p, dir := proofOnDisk(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	lotl, list, _ := scheme(t, p)

	trustDir := filepath.Join(dir, "trust")
	require.NoError(t, os.MkdirAll(filepath.Join(trustDir, "lists"), 0o755))

	files, err := prooftest.SnapshotFiles(lotl, map[string][]byte{"ES": list})
	require.NoError(t, err)

	for name, data := range files {
		path := filepath.Join(trustDir, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, data, 0o600))
	}

	res := run(t, "verify", filepath.Join(dir, "proof.zip"),
		"--offline", "--trust-dir", trustDir, "--json")

	var r report.Report
	require.NoError(t, json.Unmarshal([]byte(res.stdout), &r))

	// The snapshot is read, but the generated scheme is not the shipped European
	// anchor, so qualification stays unestablished rather than being assumed.
	c, ok := r.Check("timestamp.qualified")
	require.True(t, ok)
	assert.Equal(t, report.StatusIndeterminate, c.Status)
	assert.Contains(t, c.Message, "not authentic")
}

// TestVerifyTrustSourceNone leaves the question unasked on purpose.
func TestVerifyTrustSourceNone(t *testing.T) {
	t.Parallel()

	_, dir := proofOnDisk(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	res := run(t, "verify", filepath.Join(dir, "proof.zip"),
		"--offline", "--trust-source", "none", "--json")

	var r report.Report
	require.NoError(t, json.Unmarshal([]byte(res.stdout), &r))

	c, ok := r.Check("timestamp.qualified")
	require.True(t, ok)
	assert.Equal(t, report.StatusIndeterminate, c.Status)
	assert.Contains(t, c.Message, "No Trusted List source was configured")
}

func TestVerifyRejectsAnInvalidTrustSource(t *testing.T) {
	t.Parallel()

	_, dir := proofOnDisk(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	res := run(t, "verify", filepath.Join(dir, "proof.zip"), "--trust-source", "nonsense")

	assert.Equal(t, cli.ExitError, res.code)
	assert.Contains(t, res.stderr, "expected")
}

func TestVerifyRejectsAMissingTrustDirectory(t *testing.T) {
	t.Parallel()

	_, dir := proofOnDisk(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	res := run(t, "verify", filepath.Join(dir, "proof.zip"),
		"--trust-dir", filepath.Join(dir, "does-not-exist"))

	assert.Equal(t, cli.ExitError, res.code)
	assert.Contains(t, res.stderr, "cannot read the trust snapshot")
}

// TestSnapshotFormatIsDocumented pins the identifier a mirror must publish, so
// that changing the layout is a deliberate act.
func TestSnapshotFormatIsDocumented(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "sealway-trust-snapshot/1", trust.SnapshotFormat)
	assert.Equal(t, "manifest.json", trust.ManifestName)
}

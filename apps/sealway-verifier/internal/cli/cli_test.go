// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package cli_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealway-hq/sealway-verifier/apps/sealway-verifier/internal/cli"
	"github.com/sealway-hq/sealway-verifier/internal/prooftest"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/report"
)

type result struct {
	code   int
	stdout string
	stderr string
}

func run(t *testing.T, args ...string) result {
	t.Helper()

	var out, errOut bytes.Buffer

	code := cli.Run(t.Context(), args, cli.Streams{Out: &out, Err: &errOut})

	return result{code: code, stdout: out.String(), stderr: errOut.String()}
}

func write(t *testing.T, path string, data []byte) string {
	t.Helper()

	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, data, 0o600))

	return path
}

// proofOnDisk lays a generated proof out on disk and returns the directory.
func proofOnDisk(t *testing.T, opts prooftest.Options) (*prooftest.Proof, string) {
	t.Helper()

	p, err := prooftest.New(opts)
	require.NoError(t, err)

	dir := t.TempDir()

	write(t, filepath.Join(dir, "certificate.pdf"), p.Certificate)

	for _, f := range p.Files {
		write(t, filepath.Join(dir, "files", f.Name), f.Content)
	}

	archive, err := p.Bundle(prooftest.BundleOptions{})
	require.NoError(t, err)
	write(t, filepath.Join(dir, "proof.zip"), archive)

	return p, dir
}

func TestVerifyBundleExitsPartialWhenOffline(t *testing.T) {
	t.Parallel()

	_, dir := proofOnDisk(t, prooftest.Options{Files: prooftest.DefaultFiles(2)})

	res := run(t, "verify", filepath.Join(dir, "proof.zip"), "--offline")

	// The generated proof declares no anchor, so anchoring evidence is
	// unavailable and the run is partial rather than complete.
	assert.Equal(t, cli.ExitPartialValid, res.code)
	assert.Contains(t, res.stdout, "PARTIAL VALID")
	assert.Contains(t, res.stdout, "Source files")
	assert.Contains(t, res.stdout, "Proof Merkle tree")
	assert.Contains(t, res.stdout, "Qualified timestamp")
	assert.Contains(t, res.stdout, "Accumulator")
	assert.Contains(t, res.stdout, "Blockchain anchors")
}

func TestVerifyCertificateAloneIsPartial(t *testing.T) {
	t.Parallel()

	_, dir := proofOnDisk(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	res := run(t, "verify", filepath.Join(dir, "certificate.pdf"), "--offline")

	assert.Equal(t, cli.ExitPartialValid, res.code)
	assert.Contains(t, res.stdout, "PARTIAL VALID")
	assert.Contains(t, res.stdout, "SKIPPED")
	assert.Contains(t, res.stdout, "not provided")
}

func TestVerifyCertificateWithSource(t *testing.T) {
	t.Parallel()

	p, dir := proofOnDisk(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	res := run(t, "verify", filepath.Join(dir, "certificate.pdf"), "--offline",
		"--source", filepath.Join(dir, "files", p.Files[0].Name))

	assert.Equal(t, cli.ExitPartialValid, res.code)
	assert.Contains(t, res.stdout, p.Files[0].Name)
}

func TestVerifyCertificateWithSourcesDir(t *testing.T) {
	t.Parallel()

	p, dir := proofOnDisk(t, prooftest.Options{Files: prooftest.DefaultFiles(3)})

	res := run(t, "verify", filepath.Join(dir, "certificate.pdf"), "--offline",
		"--sources-dir", filepath.Join(dir, "files"))

	assert.Equal(t, cli.ExitPartialValid, res.code)

	for _, f := range p.Files {
		assert.Contains(t, res.stdout, f.Name)
	}
}

func TestVerifyExitsInvalidOnWrongSource(t *testing.T) {
	t.Parallel()

	p, dir := proofOnDisk(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	wrong := write(t, filepath.Join(t.TempDir(), p.Files[0].Name), []byte("tampered"))

	res := run(t, "verify", filepath.Join(dir, "certificate.pdf"), "--offline", "--source", wrong)

	assert.Equal(t, cli.ExitInvalid, res.code)
	assert.Contains(t, res.stdout, "INVALID")
}

func TestJSONOutputIsTheCanonicalReport(t *testing.T) {
	t.Parallel()

	_, dir := proofOnDisk(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	res := run(t, "verify", filepath.Join(dir, "proof.zip"), "--offline", "--json")
	require.Equal(t, cli.ExitPartialValid, res.code)

	var r report.Report
	require.NoError(t, json.Unmarshal([]byte(res.stdout), &r))

	assert.Equal(t, report.SchemaVersion, r.SchemaVersion)
	assert.Equal(t, report.ResultPartialValid, r.Result)
	assert.NotEmpty(t, r.Sections)
	assert.NotNil(t, r.Certificate)

	// The machine readable output carries no terminal presentation.
	assert.NotContains(t, res.stdout, "\x1b[")
}

// TestOutputIsUncoloredWhenNotATerminal covers the default for pipes and files,
// which is where automation reads the output.
func TestOutputIsUncoloredWhenNotATerminal(t *testing.T) {
	t.Parallel()

	_, dir := proofOnDisk(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	res := run(t, "verify", filepath.Join(dir, "proof.zip"), "--offline")
	assert.NotContains(t, res.stdout, "\x1b[")
}

func TestOperationalErrors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	cases := map[string][]string{
		"missing file":     {"verify", filepath.Join(dir, "nope.zip")},
		"directory":        {"verify", dir},
		"unsupported type": {"verify", write(t, filepath.Join(dir, "notes.txt"), []byte("hello"))},
		"no argument":      {"verify"},
		"too many args":    {"verify", "a", "b"},
		"unknown command":  {"frobnicate"},
	}

	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			res := run(t, args...)
			assert.Equal(t, cli.ExitError, res.code)
			assert.NotEmpty(t, res.stderr)
		})
	}
}

// TestBundleRejectsSourceFlags records that a bundle already carries its files,
// so combining it with supplied sources is a usage error rather than a silent
// no-op.
func TestBundleRejectsSourceFlags(t *testing.T) {
	t.Parallel()

	p, dir := proofOnDisk(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	res := run(t, "verify", filepath.Join(dir, "proof.zip"),
		"--source", filepath.Join(dir, "files", p.Files[0].Name))

	assert.Equal(t, cli.ExitError, res.code)
	assert.Contains(t, res.stderr, "already carries")
}

func TestInvalidAnchorEndpointFlag(t *testing.T) {
	t.Parallel()

	_, dir := proofOnDisk(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	res := run(t, "verify", filepath.Join(dir, "proof.zip"), "--anchor-endpoint", "nonsense")
	assert.Equal(t, cli.ExitError, res.code)
	assert.Contains(t, res.stderr, "network=url")
}

func TestTimestampRootsFlag(t *testing.T) {
	t.Parallel()

	p, dir := proofOnDisk(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	pem := "-----BEGIN CERTIFICATE-----\n" +
		base64Wrap(p.TSA.RootDER) + "-----END CERTIFICATE-----\n"
	roots := write(t, filepath.Join(dir, "roots.pem"), []byte(pem))

	res := run(t, "verify", filepath.Join(dir, "proof.zip"), "--offline",
		"--timestamp-roots", roots, "--json")
	require.Equal(t, cli.ExitPartialValid, res.code)

	var r report.Report
	require.NoError(t, json.Unmarshal([]byte(res.stdout), &r))

	c, ok := r.Check("timestamp.trust_chain")
	require.True(t, ok)
	assert.Equal(t, report.StatusValid, c.Status)
}

func TestTimestampRootsFlagErrors(t *testing.T) {
	t.Parallel()

	_, dir := proofOnDisk(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	res := run(t, "verify", filepath.Join(dir, "proof.zip"),
		"--timestamp-roots", filepath.Join(dir, "missing.pem"))
	assert.Equal(t, cli.ExitError, res.code)

	notPEM := write(t, filepath.Join(dir, "bad.pem"), []byte("not a certificate"))

	res = run(t, "verify", filepath.Join(dir, "proof.zip"), "--timestamp-roots", notPEM)
	assert.Equal(t, cli.ExitError, res.code)
	assert.Contains(t, res.stderr, "no certificate")
}

func base64Wrap(der []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	var out bytes.Buffer

	for i := 0; i < len(der); i += 3 {
		var chunk [3]byte

		n := copy(chunk[:], der[i:])
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

		if out.Len()%65 == 64 {
			out.WriteByte('\n')
		}
	}

	out.WriteByte('\n')

	return out.String()
}

func TestVersionCommand(t *testing.T) {
	t.Parallel()

	cli.SetBuildInfo("1.2.3", "abcdef", "2026-08-14")

	res := run(t, "version")
	assert.Equal(t, cli.ExitCompleteValid, res.code)
	assert.Contains(t, res.stdout, "sealway-verifier 1.2.3")
	assert.Contains(t, res.stdout, "abcdef")
}

func TestHelpDocumentsExitCodes(t *testing.T) {
	t.Parallel()

	res := run(t, "verify", "--help")
	assert.Equal(t, cli.ExitCompleteValid, res.code)
	assert.Contains(t, res.stdout, "Exit codes")
	assert.Contains(t, res.stdout, "0  complete verification")
	assert.Contains(t, res.stdout, "1  the proof is invalid")
	assert.Contains(t, res.stdout, "2  the tool could not run")
	assert.Contains(t, res.stdout, "3  partial verification")
}

func TestRootHelp(t *testing.T) {
	t.Parallel()

	res := run(t)
	assert.Contains(t, res.stdout, "sealway-verifier")
	assert.Contains(t, res.stdout, "verify")
}

// TestBundleWithoutCertificateIsAnOperationalError separates a tool level
// failure from a verification outcome: an unusable archive is not an invalid
// proof.
func TestBundleWithoutCertificateIsAnOperationalError(t *testing.T) {
	t.Parallel()

	p, err := prooftest.New(prooftest.Options{Files: prooftest.DefaultFiles(1)})
	require.NoError(t, err)

	archive, err := p.Bundle(prooftest.BundleOptions{OmitCertificate: true})
	require.NoError(t, err)

	path := write(t, filepath.Join(t.TempDir(), "proof.zip"), archive)

	res := run(t, "verify", path, "--offline")
	assert.Equal(t, cli.ExitError, res.code)
	assert.Contains(t, res.stderr, "certificate")
}

// TestInputKindIsSniffed checks the input type comes from the content, not the
// extension, so a renamed proof still verifies and a mislabelled one is refused.
func TestInputKindIsSniffed(t *testing.T) {
	t.Parallel()

	p, err := prooftest.New(prooftest.Options{Files: prooftest.DefaultFiles(1)})
	require.NoError(t, err)

	archive, err := p.Bundle(prooftest.BundleOptions{})
	require.NoError(t, err)

	dir := t.TempDir()

	// A bundle named like a certificate is still read as a bundle.
	res := run(t, "verify", write(t, filepath.Join(dir, "certificate.pdf"), archive), "--offline")
	assert.Equal(t, cli.ExitPartialValid, res.code)

	// A certificate named like a bundle is still read as a certificate.
	res = run(t, "verify", write(t, filepath.Join(dir, "proof.zip"), p.Certificate), "--offline")
	assert.Equal(t, cli.ExitPartialValid, res.code)
}

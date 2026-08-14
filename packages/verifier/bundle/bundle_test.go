// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package bundle_test

import (
	"archive/zip"
	"bytes"
	"io"
	"io/fs"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealway-hq/sealway-verifier/packages/verifier/bundle"
)

type entry struct {
	name string
	data []byte
	mode fs.FileMode
}

// buildSimpleZip writes an archive from raw entries, including names and modes
// archive/zip would not normally produce, so hostile archives can be exercised.
func buildSimpleZip(t *testing.T, entries []entry) []byte {
	t.Helper()

	var buf bytes.Buffer

	zw := zip.NewWriter(&buf)

	for _, e := range entries {
		header := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		if e.mode != 0 {
			header.SetMode(e.mode)
		}

		w, err := zw.CreateHeader(header)
		require.NoError(t, err)

		_, err = w.Write(e.data)
		require.NoError(t, err)
	}

	require.NoError(t, zw.Close())

	return buf.Bytes()
}

func open(t *testing.T, data []byte, limits bundle.Limits) (*bundle.Bundle, error) {
	t.Helper()

	return bundle.Open(bytes.NewReader(data), int64(len(data)), limits)
}

func wellFormed() []entry {
	return []entry{
		{name: "sealway-certificate-SW-2026-TEST0001.pdf", data: []byte("%PDF-1.7 certificate")},
		{name: "sealway-proof.json", data: []byte(`{"version":"1.1"}`)},
		{name: "proof-timestamp.tsr", data: []byte{0x30, 0x00}},
		{name: "files/first.bin", data: []byte("first")},
		{name: "files/second.bin", data: []byte("second")},
	}
}

func TestOpenWellFormedBundle(t *testing.T) {
	t.Parallel()

	b, err := open(t, buildSimpleZip(t, wellFormed()), bundle.Limits{})
	require.NoError(t, err)

	cert, err := b.Certificate()
	require.NoError(t, err)
	assert.Equal(t, "sealway-certificate-SW-2026-TEST0001.pdf", cert.Name)

	data, err := cert.Bytes()
	require.NoError(t, err)
	assert.Equal(t, "%PDF-1.7 certificate", string(data))

	sources := b.Sources()
	require.Len(t, sources, 2)
	assert.Equal(t, "first.bin", sources[0].Base())
	assert.Equal(t, int64(5), sources[0].Size)

	loose, ok := b.LooseCopy(bundle.LooseManifestName)
	require.True(t, ok)

	looseData, err := loose.Bytes()
	require.NoError(t, err)
	assert.JSONEq(t, `{"version":"1.1"}`, string(looseData))

	_, ok = b.LooseCopy("does-not-exist")
	assert.False(t, ok)

	assert.Len(t, b.Entries(), 5)

	_, ok = b.Entry("files/first.bin")
	assert.True(t, ok)
}

func TestEntryOpenStreams(t *testing.T) {
	t.Parallel()

	b, err := open(t, buildSimpleZip(t, wellFormed()), bundle.Limits{})
	require.NoError(t, err)

	e, ok := b.Entry("files/second.bin")
	require.True(t, ok)

	rc, err := e.Open()
	require.NoError(t, err)

	defer func() { _ = rc.Close() }()

	data, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, "second", string(data))
}

func TestCertificateSelection(t *testing.T) {
	t.Parallel()

	t.Run("missing", func(t *testing.T) {
		t.Parallel()

		b, err := open(t, buildSimpleZip(t, []entry{{name: "files/a.bin", data: []byte("a")}}), bundle.Limits{})
		require.NoError(t, err)

		_, err = b.Certificate()
		assert.ErrorIs(t, err, bundle.ErrNoCertificate)
	})

	t.Run("ambiguous", func(t *testing.T) {
		t.Parallel()

		data := buildSimpleZip(t, []entry{
			{name: "sealway-certificate-A.pdf", data: []byte("a")},
			{name: "sealway-certificate-B.pdf", data: []byte("b")},
		})

		b, err := open(t, data, bundle.Limits{})
		require.NoError(t, err)

		_, err = b.Certificate()
		assert.ErrorIs(t, err, bundle.ErrAmbiguousCertificate)
	})

	t.Run("renamed single pdf at root", func(t *testing.T) {
		t.Parallel()

		data := buildSimpleZip(t, []entry{
			{name: "my-proof.pdf", data: []byte("a")},
			{name: "files/x.bin", data: []byte("x")},
		})

		b, err := open(t, data, bundle.Limits{})
		require.NoError(t, err)

		cert, err := b.Certificate()
		require.NoError(t, err)
		assert.Equal(t, "my-proof.pdf", cert.Name)
	})

	t.Run("named certificate wins over other pdfs", func(t *testing.T) {
		t.Parallel()

		data := buildSimpleZip(t, []entry{
			{name: "sealway-certificate-A.pdf", data: []byte("a")},
			{name: "readme.pdf", data: []byte("b")},
		})

		b, err := open(t, data, bundle.Limits{})
		require.NoError(t, err)

		cert, err := b.Certificate()
		require.NoError(t, err)
		assert.Equal(t, "sealway-certificate-A.pdf", cert.Name)
	})

	t.Run("nested certificate is not considered", func(t *testing.T) {
		t.Parallel()

		data := buildSimpleZip(t, []entry{
			{name: "nested/sealway-certificate-A.pdf", data: []byte("a")},
		})

		b, err := open(t, data, bundle.Limits{})
		require.NoError(t, err)

		_, err = b.Certificate()
		assert.ErrorIs(t, err, bundle.ErrNoCertificate)
	})
}

// TestOpenRejectsUnsafeEntries covers the hostile archive cases: path traversal,
// absolute paths, Windows separators, drive letters and irregular file modes.
// Nothing is ever written to disk, but a rejected entry can never reach code
// that does.
func TestOpenRejectsUnsafeEntries(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"parent traversal":      "../escaped.txt",
		"nested traversal":      "files/../../escaped.txt",
		"deep traversal":        "a/b/../../../escaped.txt",
		"absolute path":         "/etc/passwd",
		"double slash absolute": "//etc/passwd",
		"backslash separator":   `files\..\escaped.txt`,
		"windows drive":         `C:/windows/system32/x`,
		"current directory":     "./files/a.bin",
		"trailing dot segment":  "files/./a.bin",
		"empty name":            "",
		"double slash in path":  "files//a.bin",
		"bare parent":           "..",
	}

	for name, entryName := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			data := buildSimpleZip(t, []entry{{name: entryName, data: []byte("payload")}})

			_, err := open(t, data, bundle.Limits{})
			assert.ErrorIs(t, err, bundle.ErrUnsafeEntry, "entry %q must be rejected", entryName)
		})
	}
}

func TestOpenRejectsNulByteInName(t *testing.T) {
	t.Parallel()

	data := buildSimpleZip(t, []entry{{name: "files/a\x00b.bin", data: []byte("x")}})

	_, err := open(t, data, bundle.Limits{})
	assert.ErrorIs(t, err, bundle.ErrUnsafeEntry)
}

func TestOpenRejectsSymlinks(t *testing.T) {
	t.Parallel()

	data := buildSimpleZip(t, []entry{
		{name: "files/link", data: []byte("/etc/passwd"), mode: fs.ModeSymlink | 0o777},
	})

	_, err := open(t, data, bundle.Limits{})
	assert.ErrorIs(t, err, bundle.ErrUnsafeEntry)
}

func TestOpenRejectsIrregularModes(t *testing.T) {
	t.Parallel()

	for name, mode := range map[string]fs.FileMode{
		"device": fs.ModeDevice | 0o666,
		"socket": fs.ModeSocket | 0o666,
		"pipe":   fs.ModeNamedPipe | 0o666,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			data := buildSimpleZip(t, []entry{{name: "files/x", data: []byte("x"), mode: mode}})

			_, err := open(t, data, bundle.Limits{})
			assert.ErrorIs(t, err, bundle.ErrUnsafeEntry)
		})
	}
}

func TestOpenRejectsDuplicateEntries(t *testing.T) {
	t.Parallel()

	data := buildSimpleZip(t, []entry{
		{name: "files/a.bin", data: []byte("first")},
		{name: "files/a.bin", data: []byte("second")},
	})

	_, err := open(t, data, bundle.Limits{})
	assert.ErrorIs(t, err, bundle.ErrDuplicateEntry)
}

func TestOpenAcceptsDirectoryEntries(t *testing.T) {
	t.Parallel()

	data := buildSimpleZip(t, []entry{
		{name: "files/", mode: fs.ModeDir | 0o755},
		{name: "files/a.bin", data: []byte("a")},
	})

	b, err := open(t, data, bundle.Limits{})
	require.NoError(t, err)
	assert.Len(t, b.Entries(), 1)
}

func TestOpenEnforcesEntryLimit(t *testing.T) {
	t.Parallel()

	entries := make([]entry, 0, 10)
	for i := range 10 {
		entries = append(entries, entry{name: "files/" + string(rune('a'+i)), data: []byte("x")})
	}

	_, err := open(t, buildSimpleZip(t, entries), bundle.Limits{MaxEntries: 5})
	assert.ErrorIs(t, err, bundle.ErrTooManyEntries)
}

// TestMetadataEntriesAreBounded checks that a compressed metadata entry cannot
// expand past the configured limit, which is what defeats a decompression bomb.
func TestMetadataEntriesAreBounded(t *testing.T) {
	t.Parallel()

	data := buildSimpleZip(t, []entry{
		{name: "sealway-proof.json", data: bytes.Repeat([]byte("A"), 1<<20)},
	})

	b, err := open(t, data, bundle.Limits{MaxMetadataSize: 4096})
	require.NoError(t, err)

	e, ok := b.LooseCopy("sealway-proof.json")
	require.True(t, ok)

	_, err = e.Bytes()
	assert.ErrorIs(t, err, bundle.ErrTooLarge)
}

func TestMetadataTotalBudgetIsShared(t *testing.T) {
	t.Parallel()

	data := buildSimpleZip(t, []entry{
		{name: "sealway-certificate-A.pdf", data: bytes.Repeat([]byte("A"), 8192)},
		{name: "sealway-proof.json", data: bytes.Repeat([]byte("B"), 8192)},
	})

	b, err := open(t, data, bundle.Limits{MaxTotalMetadata: 10000})
	require.NoError(t, err)

	cert, err := b.Certificate()
	require.NoError(t, err)

	_, err = cert.Bytes()
	require.NoError(t, err)

	loose, ok := b.LooseCopy("sealway-proof.json")
	require.True(t, ok)

	_, err = loose.Bytes()
	assert.ErrorIs(t, err, bundle.ErrTooLarge)
}

func TestSourceEntriesUseTheLargerLimit(t *testing.T) {
	t.Parallel()

	data := buildSimpleZip(t, []entry{
		{name: "files/big.bin", data: bytes.Repeat([]byte("A"), 100000)},
	})

	b, err := open(t, data, bundle.Limits{MaxMetadataSize: 1024, MaxSourceFileSize: 1 << 20})
	require.NoError(t, err)

	sources := b.Sources()
	require.Len(t, sources, 1)

	rc, err := sources[0].Open()
	require.NoError(t, err)

	defer func() { _ = rc.Close() }()

	n, err := io.Copy(io.Discard, rc)
	require.NoError(t, err)
	assert.Equal(t, int64(100000), n)
}

func TestOpenRejectsMalformedArchives(t *testing.T) {
	t.Parallel()

	valid := buildSimpleZip(t, wellFormed())

	cases := map[string][]byte{
		"empty":       {},
		"garbage":     []byte("this is definitely not a zip archive"),
		"truncated":   valid[:len(valid)/2],
		"header only": []byte("PK\x03\x04"),
	}

	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := bundle.Open(bytes.NewReader(data), int64(len(data)), bundle.Limits{})
			assert.Error(t, err)
		})
	}
}

func TestEmptyArchiveHasNoCertificate(t *testing.T) {
	t.Parallel()

	b, err := open(t, buildSimpleZip(t, nil), bundle.Limits{})
	require.NoError(t, err)
	assert.Empty(t, b.Entries())
	assert.Empty(t, b.Sources())

	_, err = b.Certificate()
	assert.ErrorIs(t, err, bundle.ErrNoCertificate)
}

// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

// Package bundle reads a Sealway proof bundle archive safely.
//
// A bundle is an untrusted external input. Nothing is ever extracted to disk, so
// path traversal and symlink attacks have no target; entries with unsafe names,
// irregular file modes or duplicate paths are rejected outright; and the
// resources a hostile archive can consume are bounded.
//
// The archive is a convenience container. The certificate it holds remains the
// only authoritative source of the proof manifest and of the RFC 3161 token: the
// loose copies a bundle may also carry are never used as a fallback authority.
package bundle

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// Well known paths inside a bundle.
const (
	// SourcesPrefix is the directory holding the original files.
	SourcesPrefix = "files/"
	// CertificatePrefix is the file name prefix of the certificate.
	CertificatePrefix = "sealway-certificate-"
	// CertificateSuffix is the file name suffix of the certificate.
	CertificateSuffix = ".pdf"
	// LooseManifestName is the non authoritative copy of the proof manifest.
	LooseManifestName = "sealway-proof.json"
	// LooseTimestampName is the non authoritative copy of the RFC 3161 artifact.
	LooseTimestampName = "proof-timestamp.tsr"
)

// Default resource limits applied to an untrusted archive.
const (
	DefaultMaxEntries        = 10000
	DefaultMaxMetadataSize   = 64 << 20  // 64 MiB for a single certificate or artifact
	DefaultMaxTotalMetadata  = 128 << 20 // 128 MiB for all metadata entries together
	DefaultMaxSourceFileSize = 8 << 30   // 8 GiB for a single original file
)

// Limits bounds the resources a hostile archive can consume.
//
// A zero value selects the defaults. Original files are only ever streamed, so
// their size limit guards against an endless entry rather than against memory
// exhaustion.
type Limits struct {
	MaxEntries        int
	MaxMetadataSize   int64
	MaxTotalMetadata  int64
	MaxSourceFileSize int64
}

func (l Limits) withDefaults() Limits {
	if l.MaxEntries <= 0 {
		l.MaxEntries = DefaultMaxEntries
	}

	if l.MaxMetadataSize <= 0 {
		l.MaxMetadataSize = DefaultMaxMetadataSize
	}

	if l.MaxTotalMetadata <= 0 {
		l.MaxTotalMetadata = DefaultMaxTotalMetadata
	}

	if l.MaxSourceFileSize <= 0 {
		l.MaxSourceFileSize = DefaultMaxSourceFileSize
	}

	return l
}

// Errors describing an archive that cannot be verified.
var (
	// ErrNoCertificate is returned when the archive holds no certificate.
	ErrNoCertificate = errors.New("bundle: the archive holds no Sealway certificate")
	// ErrAmbiguousCertificate is returned when several candidate certificates
	// make the authoritative one undecidable.
	ErrAmbiguousCertificate = errors.New("bundle: the archive holds several candidate certificates")
	// ErrUnsafeEntry is returned for an entry whose name or mode is unsafe.
	ErrUnsafeEntry = errors.New("bundle: the archive holds an unsafe entry")
	// ErrDuplicateEntry is returned when two entries resolve to the same path,
	// which would make the archive ambiguous.
	ErrDuplicateEntry = errors.New("bundle: the archive holds duplicate entries")
	// ErrTooManyEntries is returned when the archive holds more entries than the
	// configured limit.
	ErrTooManyEntries = errors.New("bundle: the archive holds too many entries")
	// ErrTooLarge is returned when an entry exceeds its configured size limit.
	ErrTooLarge = errors.New("bundle: an archive entry exceeds the configured size limit")
)

// Entry is one regular file of the archive.
type Entry struct {
	// Name is the cleaned slash separated path inside the archive.
	Name string
	// Size is the uncompressed size declared by the archive.
	Size int64

	file  *zip.File
	limit int64
}

// Base returns the last element of the entry path.
func (e Entry) Base() string { return path.Base(e.Name) }

// Open returns a reader over the entry content.
//
// Reading is bounded so that a declared size cannot be exceeded by a
// decompression bomb. The caller must close the returned reader.
func (e Entry) Open() (io.ReadCloser, error) {
	rc, err := e.file.Open()
	if err != nil {
		return nil, fmt.Errorf("bundle: cannot open %q: %w", e.Name, err)
	}

	return &boundedReader{rc: rc, remaining: e.limit + 1, name: e.Name, limit: e.limit}, nil
}

// Bytes reads the whole entry into memory, bounded by the entry limit.
func (e Entry) Bytes() ([]byte, error) {
	rc, err := e.Open()
	if err != nil {
		return nil, err
	}

	defer func() { _ = rc.Close() }()

	return io.ReadAll(rc)
}

type boundedReader struct {
	rc        io.ReadCloser
	remaining int64
	name      string
	limit     int64
}

func (b *boundedReader) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		return 0, fmt.Errorf("%w: %q is larger than %d bytes", ErrTooLarge, b.name, b.limit)
	}

	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}

	n, err := b.rc.Read(p)
	b.remaining -= int64(n)

	if b.remaining <= 0 && err == nil {
		return n, fmt.Errorf("%w: %q is larger than %d bytes", ErrTooLarge, b.name, b.limit)
	}

	return n, err
}

func (b *boundedReader) Close() error { return b.rc.Close() }

// Bundle is a safely enumerated proof bundle archive.
type Bundle struct {
	entries []Entry
	byName  map[string]Entry
	limits  Limits
}

// Open enumerates a proof bundle archive.
//
// The archive is read through an io.ReaderAt so that a bundle held in memory and
// a bundle on disk are handled identically, which keeps the package usable from
// a WebAssembly build.
func Open(ra io.ReaderAt, size int64, limits Limits) (*Bundle, error) {
	limits = limits.withDefaults()

	zr, err := zip.NewReader(ra, size)
	if err != nil {
		return nil, fmt.Errorf("bundle: cannot read the archive: %w", err)
	}

	if len(zr.File) > limits.MaxEntries {
		return nil, fmt.Errorf("%w: %d entries, the maximum is %d",
			ErrTooManyEntries, len(zr.File), limits.MaxEntries)
	}

	b := &Bundle{byName: make(map[string]Entry, len(zr.File)), limits: limits}

	metadataBudget := limits.MaxTotalMetadata

	for _, f := range zr.File {
		name, isDir, err := safeName(f)
		if err != nil {
			return nil, err
		}

		if isDir {
			continue
		}

		if _, dup := b.byName[name]; dup {
			return nil, fmt.Errorf("%w: %q appears more than once", ErrDuplicateEntry, name)
		}

		limit := limits.MaxSourceFileSize
		if !isSourcePath(name) {
			limit = limits.MaxMetadataSize
			if metadataBudget < limit {
				limit = metadataBudget
			}

			metadataBudget -= int64(f.UncompressedSize64) //nolint:gosec // only used as a budget
			if metadataBudget < 0 {
				metadataBudget = 0
			}
		}

		e := Entry{
			Name:  name,
			Size:  int64(f.UncompressedSize64), //nolint:gosec // compared against limits before use
			file:  f,
			limit: limit,
		}

		b.entries = append(b.entries, e)
		b.byName[name] = e
	}

	sort.Slice(b.entries, func(i, j int) bool { return b.entries[i].Name < b.entries[j].Name })

	return b, nil
}

// safeName validates an archive entry name and mode.
//
// Absolute paths, parent directory traversal, Windows style separators, drive
// letters, NUL bytes and every non regular file mode are rejected. Nothing is
// written to disk by this package, but a rejected entry can never reach code
// that does.
func safeName(f *zip.File) (name string, isDir bool, err error) {
	raw := f.Name

	if raw == "" {
		return "", false, fmt.Errorf("%w: an entry has an empty name", ErrUnsafeEntry)
	}

	if strings.ContainsRune(raw, 0) {
		return "", false, fmt.Errorf("%w: an entry name contains a NUL byte", ErrUnsafeEntry)
	}

	if strings.Contains(raw, `\`) {
		return "", false, fmt.Errorf("%w: %q contains a backslash", ErrUnsafeEntry, raw)
	}

	if strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return "", false, fmt.Errorf("%w: %q is an absolute path", ErrUnsafeEntry, raw)
	}

	if len(raw) >= 2 && raw[1] == ':' {
		return "", false, fmt.Errorf("%w: %q carries a drive letter", ErrUnsafeEntry, raw)
	}

	isDir = strings.HasSuffix(raw, "/")

	cleaned := path.Clean(raw)
	if cleaned == "." || cleaned == "/" {
		return "", true, nil
	}

	if cleaned != strings.TrimSuffix(raw, "/") {
		return "", false, fmt.Errorf("%w: %q is not a normalized path", ErrUnsafeEntry, raw)
	}

	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", false, fmt.Errorf("%w: %q escapes the archive", ErrUnsafeEntry, raw)
	}

	if !fs.ValidPath(cleaned) {
		return "", false, fmt.Errorf("%w: %q is not a valid path", ErrUnsafeEntry, raw)
	}

	if isDir {
		return cleaned, true, nil
	}

	mode := f.FileInfo().Mode()
	if !mode.IsRegular() {
		return "", false, fmt.Errorf("%w: %q is not a regular file (mode %s)", ErrUnsafeEntry, raw, mode)
	}

	return cleaned, false, nil
}

func isSourcePath(name string) bool {
	return strings.HasPrefix(name, SourcesPrefix)
}

// Entries returns every regular file of the archive, sorted by path.
func (b *Bundle) Entries() []Entry { return b.entries }

// Entry returns the entry at the given path.
func (b *Bundle) Entry(name string) (Entry, bool) {
	e, ok := b.byName[name]

	return e, ok
}

// Certificate locates the authoritative certificate of the bundle.
//
// Selection is deterministic: an entry at the archive root named
// sealway-certificate-*.pdf wins. When no such entry exists, a single PDF at the
// archive root outside the files directory is accepted, so that a renamed bundle
// still verifies. Anything ambiguous is refused rather than guessed.
func (b *Bundle) Certificate() (Entry, error) {
	var named, anyPDF []Entry

	for _, e := range b.entries {
		if strings.Contains(e.Name, "/") {
			continue // only the archive root is considered
		}

		lower := strings.ToLower(e.Name)
		if !strings.HasSuffix(lower, CertificateSuffix) {
			continue
		}

		anyPDF = append(anyPDF, e)

		if strings.HasPrefix(lower, CertificatePrefix) {
			named = append(named, e)
		}
	}

	candidates := named
	if len(candidates) == 0 {
		candidates = anyPDF
	}

	switch len(candidates) {
	case 0:
		return Entry{}, ErrNoCertificate
	case 1:
		return candidates[0], nil
	default:
		return Entry{}, fmt.Errorf("%w: %s", ErrAmbiguousCertificate, strings.Join(names(candidates), ", "))
	}
}

// Sources returns the original files carried by the bundle, sorted by path.
func (b *Bundle) Sources() []Entry {
	var out []Entry

	for _, e := range b.entries {
		if isSourcePath(e.Name) {
			out = append(out, e)
		}
	}

	return out
}

// LooseCopy returns the non authoritative copy of a metadata artifact carried at
// the archive root.
//
// These copies exist so that humans and third party tooling can reach the proof
// data easily. The verifier only ever compares them with the authoritative
// artifacts embedded in the certificate; it never uses them as a fallback.
func (b *Bundle) LooseCopy(name string) (Entry, bool) {
	e, ok := b.byName[name]

	return e, ok
}

func names(entries []Entry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name)
	}

	return out
}

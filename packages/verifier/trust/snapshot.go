// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package trust

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"
)

// SnapshotFormat is the version of the on-disk and mirrored snapshot layout.
const SnapshotFormat = "sealway-trust-snapshot/1"

// ManifestName is the file naming a snapshot's contents.
const ManifestName = "manifest.json"

// Manifest describes a snapshot of trust material.
//
// The snapshot stores the official signed documents unchanged and records where
// each came from and what it hashes to. It deliberately does not store a list of
// certificates somebody decided to trust: a client must be able to verify the
// European signatures itself, so what is mirrored is the evidence, not a verdict
// about it.
type Manifest struct {
	// Format identifies the layout, so a reader can refuse what it does not
	// understand.
	Format string `json:"format"`
	// GeneratedAt is when the snapshot was assembled.
	GeneratedAt time.Time `json:"generated_at"`
	// LOTL is the European List of Trusted Lists.
	LOTL Entry `json:"lotl"`
	// Lists are the national lists, keyed by scheme territory.
	Lists map[string]Entry `json:"lists"`
}

// Entry describes one stored document.
type Entry struct {
	// Path is where the bytes live inside the snapshot, relative to the
	// manifest.
	Path string `json:"path"`
	// SourceURL is where the document was published.
	SourceURL string `json:"source_url"`
	// SHA256 is the lowercase hexadecimal digest of the stored bytes, so a
	// reader can detect material altered in transit or at rest.
	SHA256 string `json:"sha256"`
	// Size is the length in bytes.
	Size int64 `json:"size"`
	// Territory is the scheme territory, empty for the list of lists.
	Territory string `json:"territory,omitempty"`
	// Sequence is the list sequence number, which increases with every issue. A
	// reader can refuse a snapshot that would move it backwards.
	Sequence uint64 `json:"sequence,omitempty"`
	// IssueDate is when the list was issued.
	IssueDate time.Time `json:"issue_date,omitzero"`
	// NextUpdate is when the operator undertook to publish again.
	NextUpdate time.Time `json:"next_update,omitzero"`
}

// ErrUnsupportedSnapshot is returned for a snapshot layout this version does not
// understand.
var ErrUnsupportedSnapshot = errors.New("trust: unsupported snapshot format")

// Snapshot reads trust material from a filesystem.
//
// It takes an fs.FS rather than a directory name, so the core never needs the
// operating system: a command line tool passes os.DirFS, a desktop application
// may pass an embedded filesystem, and a browser build may pass one backed by
// whatever storage the host provides.
type Snapshot struct {
	fsys fs.FS
	name string
}

// NewSnapshot returns a provider reading a snapshot from a filesystem.
func NewSnapshot(fsys fs.FS, name string) *Snapshot {
	return &Snapshot{fsys: fsys, name: name}
}

// Describe implements Provider.
func (s *Snapshot) Describe() string {
	if s == nil {
		return "no trust material provider"
	}

	if s.name == "" {
		return "a local trust snapshot"
	}

	return "the trust snapshot at " + s.name
}

// Material implements Provider.
//
// Reading a snapshot needs no network, so it answers the same way offline and
// online. Every stored document is checked against the digest the manifest
// declares before being returned.
func (s *Snapshot) Material(_ context.Context, req Request) (*Material, error) {
	if s == nil || s.fsys == nil {
		return nil, ErrUnavailable
	}

	raw, err := fs.ReadFile(s.fsys, ManifestName)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read %s: %w", ErrUnavailable, ManifestName, err)
	}

	var manifest Manifest
	if err = json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("trust: cannot read the snapshot manifest: %w", err)
	}

	if manifest.Format != SnapshotFormat {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedSnapshot, manifest.Format)
	}

	lotl, err := s.read(manifest.LOTL)
	if err != nil {
		return nil, err
	}

	material := &Material{
		LOTL:        lotl,
		Lists:       map[string][]byte{},
		Source:      s.Describe(),
		RetrievedAt: manifest.GeneratedAt,
	}

	territory := strings.ToUpper(strings.TrimSpace(req.Territory))

	for t, entry := range manifest.Lists {
		if territory != "" && !strings.EqualFold(t, territory) {
			continue
		}

		data, err := s.read(entry)
		if err != nil {
			return nil, err
		}

		material.Lists[strings.ToUpper(t)] = data
	}

	if territory != "" && len(material.Lists) == 0 {
		return nil, fmt.Errorf("%w: the snapshot carries no list for %s", ErrUnavailable, territory)
	}

	return material, nil
}

func (s *Snapshot) read(e Entry) ([]byte, error) {
	if e.Path == "" {
		return nil, fmt.Errorf("%w: the manifest names no path", ErrUnavailable)
	}

	clean := path.Clean(e.Path)
	if clean != e.Path || strings.HasPrefix(clean, "..") || path.IsAbs(clean) {
		return nil, fmt.Errorf("trust: the manifest path %q is not a plain relative path", e.Path)
	}

	data, err := fs.ReadFile(s.fsys, clean)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read %s: %w", ErrUnavailable, clean, err)
	}

	if err := CheckDigest(data, e.SHA256); err != nil {
		return nil, fmt.Errorf("%s: %w", clean, err)
	}

	return data, nil
}

// BuildManifest assembles a manifest describing material, so that a snapshot can
// be produced by whatever tool the operator prefers.
func BuildManifest(m *Material, sources map[string]string, generatedAt time.Time) *Manifest {
	manifest := &Manifest{
		Format:      SnapshotFormat,
		GeneratedAt: generatedAt.UTC(),
		Lists:       map[string]Entry{},
	}

	manifest.LOTL = Entry{
		Path:      "lotl.xml",
		SourceURL: sources["lotl"],
		SHA256:    Digest(m.LOTL),
		Size:      int64(len(m.LOTL)),
	}

	territories := make([]string, 0, len(m.Lists))
	for t := range m.Lists {
		territories = append(territories, t)
	}

	sort.Strings(territories)

	for _, t := range territories {
		data := m.Lists[t]
		manifest.Lists[t] = Entry{
			Path:      "lists/" + strings.ToLower(t) + ".xml",
			SourceURL: sources[t],
			SHA256:    Digest(data),
			Size:      int64(len(data)),
			Territory: t,
		}
	}

	return manifest
}

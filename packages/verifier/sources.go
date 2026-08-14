// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package verifier

import (
	"bytes"
	"crypto/sha512"
	"fmt"
	"io"
	"path"
	"sort"

	"golang.org/x/text/unicode/norm"

	"github.com/sealway-hq/sealway-verifier/packages/verifier/proof"
)

// hashBufferSize is the chunk size used to stream a source file through the
// hash. Source files may be large media files, so they are never loaded into
// memory in full.
const hashBufferSize = 1 << 20 // 1 MiB

// HashSource computes the proof integrity hash of a file.
//
// The proof integrity hash is the SHA-512 of the raw file bytes. There is no
// canonicalization, no content type specific digest and nothing derived from the
// file name, the MIME type or any metadata. The reader is consumed by streaming,
// so the file is never held in memory in full.
func HashSource(r io.Reader) ([]byte, error) {
	h := sha512.New()

	if _, err := io.CopyBuffer(h, r, make([]byte, hashBufferSize)); err != nil {
		return nil, fmt.Errorf("verifier: cannot read the source file: %w", err)
	}

	return h.Sum(nil), nil
}

// matchKind records how a source file was paired with a certified item.
type matchKind string

const (
	matchByName    matchKind = "name"
	matchByContent matchKind = "content"
)

// sourceMatch pairs one certified item with the supplied file representing it.
type sourceMatch struct {
	source Source
	hash   []byte
	kind   matchKind
	err    error
}

// sourceFailure records a supplied file that could not be read at all.
type sourceFailure struct {
	name string
	err  error
}

// matchResult is the outcome of resolving the supplied files against the
// certified items.
type matchResult struct {
	// byPosition maps a certified item position to the file representing it.
	byPosition map[int]sourceMatch
	// unmatched lists explicitly designated files that correspond to no
	// certified item.
	unmatched []string
	// failed lists supplied files that could not be read.
	failed []sourceFailure
	// ignored counts discovered files that correspond to no certified item and
	// were therefore not considered part of the proof.
	ignored int
	// duplicates lists supplied files claiming a certified name already taken by
	// another supplied file.
	duplicates []string
}

// matchSources pairs the supplied files with the certified items.
//
// Matching is deterministic and never fuzzy. Two rules are applied in order:
//
//  1. a file whose base name is exactly the certified file name is paired with
//     that item. Names are compared after Unicode NFC normalization, so a name
//     stored decomposed on macOS and composed elsewhere is recognised as the
//     same name. A certified name shared by several items is not usable for
//     matching and is skipped, so an ambiguous name can never pair a file with
//     the wrong item;
//  2. a file that no certified name claimed is then paired by content, using its
//     SHA-512, which is the only truly authoritative link between a file and a
//     certified item. Only explicitly designated files reach this rule, so
//     pointing the verifier at a large directory never turns into hashing
//     everything inside it.
//
// Pairing a file with an item asserts nothing about the file: the caller still
// recomputes its digest and compares it with the certified leaf.
func matchSources(items []proof.Item, sources []Source, progress ProgressFunc) *matchResult {
	res := &matchResult{byPosition: make(map[int]sourceMatch, len(items))}

	byName := indexItemNames(items)
	claimed := make(map[int]bool, len(items))
	remaining := make([]Source, 0, len(sources))

	for _, s := range sources {
		pos, ok := byName[normalizeName(s.Name)]

		switch {
		case !ok:
			remaining = append(remaining, s)
		case claimed[pos]:
			res.duplicates = append(res.duplicates, s.Name)
		default:
			claimed[pos] = true
			res.byPosition[pos] = sourceMatch{source: s, kind: matchByName}
		}
	}

	res.matchByContent(items, remaining, claimed)
	res.hashPending(progress)

	sort.Strings(res.unmatched)
	sort.Strings(res.duplicates)

	return res
}

func (r *matchResult) matchByContent(items []proof.Item, remaining []Source, claimed map[int]bool) {
	byLeaf := indexItemLeaves(items, claimed)

	for _, s := range remaining {
		if !s.Explicit {
			r.ignored++

			continue
		}

		sum, err := hashSource(s)
		if err != nil {
			r.failed = append(r.failed, sourceFailure{name: s.Name, err: err})

			continue
		}

		pos, ok := byLeaf[string(sum)]
		if !ok || claimed[pos] {
			r.unmatched = append(r.unmatched, s.Name)

			continue
		}

		claimed[pos] = true
		r.byPosition[pos] = sourceMatch{source: s, hash: sum, kind: matchByContent}
	}
}

// hashPending computes the digest of every paired file that has not been hashed
// yet, streaming each file exactly once.
func (r *matchResult) hashPending(progress ProgressFunc) {
	positions := make([]int, 0, len(r.byPosition))
	for p := range r.byPosition {
		positions = append(positions, p)
	}

	sort.Ints(positions)

	for i, p := range positions {
		m := r.byPosition[p]
		if m.hash != nil || m.err != nil {
			continue
		}

		reportProgress(progress, Progress{
			Stage:   StageSources,
			Item:    m.source.Name,
			Current: i + 1,
			Total:   len(positions),
		})

		m.hash, m.err = hashSource(m.source)
		r.byPosition[p] = m
	}
}

func hashSource(s Source) ([]byte, error) {
	rc, err := s.Open()
	if err != nil {
		return nil, fmt.Errorf("verifier: cannot open %q: %w", s.Name, err)
	}

	defer func() { _ = rc.Close() }()

	return HashSource(rc)
}

// indexItemNames maps a normalized certified file name to the position of the
// item carrying it. Names shared by several items are excluded.
func indexItemNames(items []proof.Item) map[string]int {
	counts := make(map[string]int, len(items))
	index := make(map[string]int, len(items))

	for _, it := range items {
		name := normalizeName(it.Filename)
		if name == "" {
			continue
		}

		counts[name]++
		index[name] = it.Position
	}

	for name, n := range counts {
		if n > 1 {
			delete(index, name)
		}
	}

	return index
}

// indexItemLeaves maps a certified leaf digest to the position of the item
// carrying it, skipping items that are already paired.
func indexItemLeaves(items []proof.Item, claimed map[int]bool) map[string]int {
	index := make(map[string]int, len(items))

	for _, it := range items {
		if claimed[it.Position] || it.LeafHash.IsZero() {
			continue
		}

		key := string(it.LeafHash.Bytes())
		if _, dup := index[key]; dup {
			continue // two items certify identical content: name matching decides
		}

		index[key] = it.Position
	}

	return index
}

// normalizeName reduces a path to the base name used for matching.
//
// Only the base name is compared, because the certified name is a file name
// while the supplied file may sit anywhere. Normalizing to Unicode NFC keeps the
// comparison stable across filesystems that store names decomposed.
func normalizeName(name string) string {
	if name == "" {
		return ""
	}

	base := path.Base(name)
	if base == "." || base == "/" {
		return ""
	}

	return norm.NFC.String(base)
}

// equalHash reports whether a computed digest matches a certified one.
func equalHash(computed []byte, certified proof.Hash) bool {
	return bytes.Equal(computed, certified.Bytes())
}

func reportProgress(progress ProgressFunc, p Progress) {
	if progress != nil {
		progress(p)
	}
}

// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package proof

import (
	"fmt"
	"sort"
	"strings"
)

// Issue is a single manifest validation problem.
type Issue struct {
	// Field is a dotted path into the manifest, for example "items[2].leaf_hash".
	Field string `json:"field"`
	// Message describes what is wrong with that field.
	Message string `json:"message"`
}

// String renders the issue as "field: message".
func (i Issue) String() string { return i.Field + ": " + i.Message }

// ValidationError aggregates every problem found in a manifest so that a caller
// sees all of them at once instead of only the first.
type ValidationError struct {
	Issues []Issue
}

// Error implements the error interface.
func (e *ValidationError) Error() string {
	if e == nil || len(e.Issues) == 0 {
		return "manifest is invalid"
	}

	parts := make([]string, 0, len(e.Issues))
	for _, i := range e.Issues {
		parts = append(parts, i.String())
	}

	return "manifest is invalid: " + strings.Join(parts, "; ")
}

type validator struct {
	issues []Issue
}

func (v *validator) add(field, format string, args ...any) {
	v.issues = append(v.issues, Issue{Field: field, Message: fmt.Sprintf(format, args...)})
}

// Validate checks the structural and internal consistency of the manifest.
//
// It reports unsupported schema versions, malformed digests, contradictory
// roots, duplicate or non contiguous item positions, inconsistent leaf indices
// and impossible inclusion paths. It never repairs a malformed value.
//
// Validate does not perform any cryptographic verification: recomputing digests
// and rebuilding Merkle trees is the job of the verification pipeline.
func (m *Manifest) Validate() error {
	v := &validator{}

	v.validateVersion(m)
	v.validateProof(m)
	v.validateItems(m)
	v.validateNotarization(m)

	if len(v.issues) == 0 {
		return nil
	}

	return &ValidationError{Issues: v.issues}
}

func (v *validator) validateVersion(m *Manifest) {
	major, err := m.MajorVersion()
	if err != nil {
		v.add("version", "%s", err.Error())

		return
	}

	if major != SupportedMajorVersion {
		v.add("version", "unsupported schema major version %d (this verifier supports version %d)",
			major, SupportedMajorVersion)
	}
}

func (v *validator) validateProof(m *Manifest) {
	p := &m.Proof

	if strings.TrimSpace(p.PublicID) == "" {
		v.add("proof.public_id", "is required")
	}

	if !isSHA512Name(p.HashAlgorithm) {
		v.add("proof.hash_algorithm", "unsupported hash algorithm %q (SHA-512 is required)", p.HashAlgorithm)
	}

	v.requireSHA512("proof.merkle_root", p.MerkleRoot, true)

	if p.ItemCount != len(m.Items) {
		v.add("proof.item_count", "declares %d items but the manifest carries %d", p.ItemCount, len(m.Items))
	}

	if p.TotalSizeBytes < 0 {
		v.add("proof.total_size_bytes", "must not be negative")
	}
}

func (v *validator) validateItems(m *Manifest) {
	if len(m.Items) == 0 {
		v.add("items", "at least one certified item is required")

		return
	}

	if len(m.Items) > MaxItems {
		v.add("items", "carries %d items which exceeds the maximum of %d", len(m.Items), MaxItems)

		return
	}

	positions := make(map[int]int, len(m.Items))
	sorted := m.ItemsByPosition()
	rank := make(map[int]int, len(sorted))

	for i, it := range sorted {
		rank[it.Position] = i
	}

	for i, it := range m.Items {
		field := fmt.Sprintf("items[%d]", i)

		if it.Position < 0 {
			v.add(field+".position", "must not be negative")
		}

		if first, dup := positions[it.Position]; dup {
			v.add(field+".position", "duplicates the position of items[%d]", first)
		} else {
			positions[it.Position] = i
		}

		if it.SizeBytes < 0 {
			v.add(field+".size_bytes", "must not be negative")
		}

		v.requireSHA512(field+".leaf_hash", it.LeafHash, true)
		v.requireSHA512(field+".hash_sha512", it.HashSHA512, false)

		if !it.HashSHA512.IsZero() && !it.LeafHash.IsZero() && !it.HashSHA512.Equal(it.LeafHash) {
			v.add(field+".leaf_hash", "does not match hash_sha512: the Merkle leaf of an item is the "+
				"SHA-512 of its raw bytes")
		}

		v.validateMerkleProof(field+".merkle_proof", it.MerkleProof, rank[it.Position], len(m.Items))
	}

	v.validateContiguity(positions, len(m.Items))
}

func (v *validator) validateContiguity(positions map[int]int, count int) {
	if len(positions) != count {
		return // duplicates already reported
	}

	all := make([]int, 0, len(positions))
	for p := range positions {
		all = append(all, p)
	}

	sort.Ints(all)

	for i, p := range all {
		if p != i {
			v.add("items.position", "item positions must be the contiguous range 0..%d, found %v",
				count-1, all)

			return
		}
	}
}

func (v *validator) validateMerkleProof(field string, p *MerkleProof, expectedIndex, leafCount int) {
	if p == nil {
		return // an absent individual proof is reported as a skipped check, not a validation error
	}

	if p.HashAlgorithm != "" && !isSHA512Name(p.HashAlgorithm) {
		v.add(field+".hash_algorithm", "unsupported hash algorithm %q (SHA-512 is required)", p.HashAlgorithm)
	}

	if p.LeafIndex < 0 || p.LeafIndex >= leafCount {
		v.add(field+".leaf_index", "leaf index %d is out of range for %d leaves", p.LeafIndex, leafCount)
	} else if expectedIndex >= 0 && p.LeafIndex != expectedIndex {
		v.add(field+".leaf_index", "leaf index %d does not match the rank %d of the item in ascending "+
			"position order", p.LeafIndex, expectedIndex)
	}

	if len(p.Siblings) > MaxSiblings {
		v.add(field+".siblings", "carries %d siblings which exceeds the maximum of %d",
			len(p.Siblings), MaxSiblings)

		return
	}

	if len(p.Siblings) == 0 {
		v.add(field+".siblings", "an inclusion path requires at least one sibling")
	}

	for i, s := range p.Siblings {
		sf := fmt.Sprintf("%s.siblings[%d]", field, i)

		switch s.Position {
		case SiblingLeft, SiblingRight:
		default:
			v.add(sf+".position", "invalid sibling direction %q (expected %q or %q)",
				s.Position, SiblingLeft, SiblingRight)
		}

		v.requireSHA512(sf+".hash", s.Hash, true)
	}
}

func (v *validator) validateNotarization(m *Manifest) {
	n := &m.Notarization

	if n.Algorithm != "" && !isSHA512Name(n.Algorithm) {
		v.add("notarization.algorithm", "unsupported hash algorithm %q (SHA-512 is required)", n.Algorithm)
	}

	v.requireSHA512("notarization.merkle_root", n.MerkleRoot, true)
	v.requireSHA512("notarization.accumulator_root", n.AccumulatorRoot, true)
	v.requireSHA512("notarization.hash", n.Hash, false)

	if !n.MerkleRoot.IsZero() && !m.Proof.MerkleRoot.IsZero() && !n.MerkleRoot.Equal(m.Proof.MerkleRoot) {
		v.add("notarization.merkle_root", "contradicts proof.merkle_root")
	}

	if !n.Hash.IsZero() && !m.Proof.MerkleRoot.IsZero() && !n.Hash.Equal(m.Proof.MerkleRoot) {
		v.add("notarization.hash", "contradicts proof.merkle_root: the notarized hash is the proof "+
			"Merkle root")
	}

	// The accumulator inclusion proof always carries exactly one leaf: the proof
	// Merkle root. Its rank inside the accumulator is not derivable from the
	// manifest, so only the structural shape is validated here.
	v.validateMerkleProof("notarization.inclusion_proof", n.InclusionProof, -1, 1<<31-1)

	for i, a := range n.BlockchainAnchors {
		field := fmt.Sprintf("notarization.blockchain_anchors[%d]", i)

		if strings.TrimSpace(a.ProviderName) == "" {
			v.add(field+".provider_name", "is required")
		}

		if strings.TrimSpace(a.TransactionID) == "" {
			v.add(field+".transaction_id", "is required")
		}
	}
}

func (v *validator) requireSHA512(field string, h Hash, required bool) {
	if h.IsZero() {
		if required {
			v.add(field, "is required")
		}

		return
	}

	if len(h) != SHA512Size {
		v.add(field, "must be a SHA-512 digest of %d bytes (%d hexadecimal characters), got %d bytes",
			SHA512Size, SHA512Size*2, len(h))
	}
}

// isSHA512Name reports whether the given algorithm name designates SHA-512.
//
// The public format has used both "SHA-512" and "SHA512"; both spellings are
// accepted and every other value is rejected.
func isSHA512Name(name string) bool {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "SHA-512", "SHA512":
		return true
	default:
		return false
	}
}

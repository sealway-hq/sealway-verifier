// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package verifier

import (
	"bytes"
	"fmt"
	"strconv"

	"github.com/sealway-hq/sealway-verifier/packages/verifier/proof"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/report"
)

// MerkleInput asks one of two questions about the Sealway Merkle profile.
//
// With Leaves, the tree is rebuilt and its root reported, and compared with Root
// when one is given. With Leaf and Path, an inclusion path is checked against
// Root. Supplying neither, or both, is a caller mistake rather than a verdict.
type MerkleInput struct {
	// Leaves are the raw digests, in ascending certified item position order.
	Leaves [][]byte
	// Leaf is the digest whose inclusion is being checked.
	Leaf []byte
	// Path is the inclusion path of Leaf, each sibling with the side it sits on.
	Path []MerkleSibling
	// Root is the root to compare against. Optional when rebuilding from leaves,
	// required when checking a path: a path proves inclusion in something, and
	// without a root there is nothing for it to prove inclusion in.
	Root []byte
}

// VerifyMerkle answers a question about the Merkle profile alone.
//
// The profile has two rules that an independent implementation reliably gets
// wrong, and both are applied here by the same code the full verification uses:
// an incomplete level duplicates its last node, including a tree of one leaf,
// and an internal node hashes the raw digest bytes of its children rather than
// their hexadecimal text.
func VerifyMerkle(in MerkleInput) (*Report, error) {
	hasLeaves := len(in.Leaves) > 0
	hasPath := len(in.Leaf) > 0

	switch {
	case hasLeaves && hasPath:
		return nil, fmt.Errorf("%w: supply either leaves to rebuild a tree, or a leaf and its "+
			"path to check, not both", ErrInvalidInput)
	case !hasLeaves && !hasPath:
		return nil, fmt.Errorf("%w: supply either leaves to rebuild a tree, or a leaf and its "+
			"path to check", ErrInvalidInput)
	}

	b := report.NewBuilder()

	if hasLeaves {
		rebuildMerkle(b, in)
	} else {
		checkMerklePath(b, in)
	}

	return b.Build(), nil
}

// rebuildMerkle recomputes a root from leaves, and compares it when the caller
// said what they expected.
func rebuildMerkle(b *report.Builder, in MerkleInput) {
	const (
		id    = "proof_merkle.root"
		title = "Merkle root"
	)

	root, err := ComputeMerkleRoot(in.Leaves)
	if err != nil {
		b.Add(report.SectionProofMerkle, sectionMerkleTitle,
			report.NewInvalid(id, title, "The tree could not be built: "+err.Error()))

		return
	}

	details := map[string]string{
		"leaves":        strconv.Itoa(len(in.Leaves)),
		"computed_root": proof.Hash(root).String(),
	}

	if len(in.Root) == 0 {
		b.Add(report.SectionProofMerkle, sectionMerkleTitle,
			report.NewOutOfScope(id, title, fmt.Sprintf(
				"The %d supplied digests build a tree whose root is %s. No expected root was "+
					"given, so the value was computed but compared with nothing.",
				len(in.Leaves), proof.Hash(root).String())).
				WithDetails(details))

		return
	}

	details["expected_root"] = proof.Hash(in.Root).String()

	if !bytes.Equal(root, in.Root) {
		b.Add(report.SectionProofMerkle, sectionMerkleTitle,
			report.NewInvalid(id, title,
				"The supplied digests do not build the expected root. Either a digest is wrong, "+
					"or they are not in the order the proof certifies.").
				WithDetails(details))

		return
	}

	b.Add(report.SectionProofMerkle, sectionMerkleTitle,
		report.NewValid(id, title, fmt.Sprintf(
			"The %d supplied digests rebuild the expected root exactly.", len(in.Leaves))).
			WithDetails(details))
}

// checkMerklePath verifies that one leaf belongs to a tree with the given root.
func checkMerklePath(b *report.Builder, in MerkleInput) {
	const (
		id    = "proof_merkle.item_proofs"
		title = "Inclusion path"
	)

	if len(in.Root) == 0 {
		b.Add(report.SectionProofMerkle, sectionMerkleTitle,
			report.NewSkipped(id, title,
				"No root was supplied. An inclusion path proves membership of a particular tree, "+
					"so without its root there is nothing for it to prove membership of."))

		return
	}

	details := map[string]string{
		"leaf":        proof.Hash(in.Leaf).String(),
		"root":        proof.Hash(in.Root).String(),
		"path_length": strconv.Itoa(len(in.Path)),
	}

	ok, err := VerifyMerkleProof(in.Leaf, in.Path, in.Root)
	if err != nil {
		b.Add(report.SectionProofMerkle, sectionMerkleTitle,
			report.NewInvalid(id, title, "The inclusion path could not be read: "+err.Error()).
				WithDetails(details))

		return
	}

	if !ok {
		b.Add(report.SectionProofMerkle, sectionMerkleTitle,
			report.NewInvalid(id, title,
				"Folding the leaf along the supplied path does not reach the root. The leaf is "+
					"not in this tree, or the path does not belong to it.").
				WithDetails(details))

		return
	}

	b.Add(report.SectionProofMerkle, sectionMerkleTitle,
		report.NewValid(id, title,
			"Folding the leaf along the supplied path reaches the root exactly, so the leaf is "+
				"in that tree.").
			WithDetails(details))
}

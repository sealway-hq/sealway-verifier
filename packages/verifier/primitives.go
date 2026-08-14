// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package verifier

import (
	"github.com/sealway-hq/sealway-verifier/packages/verifier/merkle"
)

// MerkleSibling is one step of a Merkle inclusion path.
type MerkleSibling = merkle.Sibling

// MerkleDirection indicates on which side of the current node a sibling sits.
type MerkleDirection = merkle.Direction

// Sibling directions of a Merkle inclusion path.
const (
	// MerkleLeft combines the sibling to the left: SHA-512(0x01 || sibling || current).
	MerkleLeft = merkle.Left
	// MerkleRight combines the sibling to the right: SHA-512(0x01 || current || sibling).
	MerkleRight = merkle.Right
)

// ComputeMerkleRoot builds the Sealway proof Merkle tree over the given leaves
// and returns its root.
//
// Leaves are raw SHA-512 digests in ascending certified item position order.
// This is the same operation the verifier performs internally, exposed so that a
// standalone Merkle root calculator can be built on top of it.
func ComputeMerkleRoot(leaves [][]byte) ([]byte, error) {
	return merkle.ComputeRoot(leaves)
}

// GenerateMerkleProof builds the tree over the given leaves and returns the
// inclusion path of the leaf at the given index, together with the root.
//
// It backs a standalone inclusion path calculator. The verifier itself only ever
// verifies paths it did not generate.
func GenerateMerkleProof(leaves [][]byte, index int) (siblings []MerkleSibling, root []byte, err error) {
	return merkle.GenerateProof(leaves, index)
}

// VerifyMerkleProof reports whether an inclusion path proves that the leaf
// belongs to the tree with the given root.
//
// An error is returned only for a malformed input. A well formed path that does
// not reconstruct the root returns false with a nil error.
func VerifyMerkleProof(leaf []byte, siblings []MerkleSibling, root []byte) (bool, error) {
	return merkle.VerifyProof(leaf, siblings, root)
}

// MerkleRootFromProof recomputes the root reachable from a leaf through an
// inclusion path, without comparing it with anything.
func MerkleRootFromProof(leaf []byte, siblings []MerkleSibling) ([]byte, error) {
	return merkle.RootFromProof(leaf, siblings)
}

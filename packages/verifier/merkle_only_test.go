// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package verifier_test

import (
	"crypto/sha512"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealway-hq/sealway-verifier/packages/verifier"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/report"
)

func digests(n int) [][]byte {
	out := make([][]byte, 0, n)

	for i := range n {
		sum := sha512.Sum512([]byte{byte(i)})
		out = append(out, sum[:])
	}

	return out
}

// TestVerifyMerkleRebuildsTheRoot covers the mode a caller uses to check that a
// set of digests really is what a proof certifies.
func TestVerifyMerkleRebuildsTheRoot(t *testing.T) {
	t.Parallel()

	leaves := digests(5)

	root, err := verifier.ComputeMerkleRoot(leaves)
	require.NoError(t, err)

	r, err := verifier.VerifyMerkle(verifier.MerkleInput{Leaves: leaves, Root: root})
	require.NoError(t, err)

	assert.Equal(t, report.StatusValid, statusOf(t, r, "proof_merkle.root"))
	assert.Equal(t, report.ResultCompleteValid, r.Result)
}

// TestVerifyMerkleRejectsTheWrongRoot is the half that matters: a comparison
// that cannot fail is not a check.
func TestVerifyMerkleRejectsTheWrongRoot(t *testing.T) {
	t.Parallel()

	leaves := digests(5)

	root, err := verifier.ComputeMerkleRoot(leaves)
	require.NoError(t, err)

	wrong := make([]byte, len(root))
	copy(wrong, root)
	wrong[0] ^= 0xff

	r, err := verifier.VerifyMerkle(verifier.MerkleInput{Leaves: leaves, Root: wrong})
	require.NoError(t, err)

	assert.Equal(t, report.StatusInvalid, statusOf(t, r, "proof_merkle.root"))
	assert.Equal(t, report.ResultInvalid, r.Result)
}

// TestVerifyMerkleRejectsReorderedLeaves pins the ordering rule, which is the
// one a caller reimplementing the profile is most likely to lose.
func TestVerifyMerkleRejectsReorderedLeaves(t *testing.T) {
	t.Parallel()

	leaves := digests(4)

	root, err := verifier.ComputeMerkleRoot(leaves)
	require.NoError(t, err)

	swapped := [][]byte{leaves[1], leaves[0], leaves[2], leaves[3]}

	r, err := verifier.VerifyMerkle(verifier.MerkleInput{Leaves: swapped, Root: root})
	require.NoError(t, err)

	assert.Equal(t, report.StatusInvalid, statusOf(t, r, "proof_merkle.root"))
}

// TestVerifyMerkleWithoutAnExpectedRootComputesButClaimsNothing keeps a
// calculator from reading as a verdict.
func TestVerifyMerkleWithoutAnExpectedRootComputesButClaimsNothing(t *testing.T) {
	t.Parallel()

	leaves := digests(3)

	root, err := verifier.ComputeMerkleRoot(leaves)
	require.NoError(t, err)

	r, err := verifier.VerifyMerkle(verifier.MerkleInput{Leaves: leaves})
	require.NoError(t, err)

	c, ok := r.Check("proof_merkle.root")
	require.True(t, ok)

	assert.Equal(t, report.StatusSkipped, c.Status, "computing is not concluding")
	assert.False(t, c.AffectsCompleteness)
	assert.Equal(t, hexOf(root), c.Details["computed_root"])
}

// TestVerifyMerkleFoldsAnInclusionPath covers the partial mode.
func TestVerifyMerkleFoldsAnInclusionPath(t *testing.T) {
	t.Parallel()

	leaves := digests(6)

	siblings, root, err := verifier.GenerateMerkleProof(leaves, 4)
	require.NoError(t, err)

	r, err := verifier.VerifyMerkle(verifier.MerkleInput{
		Leaf: leaves[4], Path: siblings, Root: root,
	})
	require.NoError(t, err)

	assert.Equal(t, report.StatusValid, statusOf(t, r, "proof_merkle.item_proofs"))
}

// TestVerifyMerkleRejectsAPathForAnotherLeaf keeps the path bound to the leaf it
// was generated for.
func TestVerifyMerkleRejectsAPathForAnotherLeaf(t *testing.T) {
	t.Parallel()

	leaves := digests(6)

	siblings, root, err := verifier.GenerateMerkleProof(leaves, 4)
	require.NoError(t, err)

	r, err := verifier.VerifyMerkle(verifier.MerkleInput{
		Leaf: leaves[1], Path: siblings, Root: root,
	})
	require.NoError(t, err)

	assert.Equal(t, report.StatusInvalid, statusOf(t, r, "proof_merkle.item_proofs"))
}

// TestVerifyMerkleRefusesAPathWithNoRoot states why: a path proves membership of
// a particular tree, and without its root there is no tree.
func TestVerifyMerkleRefusesAPathWithNoRoot(t *testing.T) {
	t.Parallel()

	leaves := digests(4)

	siblings, _, err := verifier.GenerateMerkleProof(leaves, 0)
	require.NoError(t, err)

	r, err := verifier.VerifyMerkle(verifier.MerkleInput{Leaf: leaves[0], Path: siblings})
	require.NoError(t, err)

	assert.Equal(t, report.StatusSkipped, statusOf(t, r, "proof_merkle.item_proofs"))
}

// TestVerifyMerkleRefusesAnAmbiguousRequest keeps a caller mistake an
// operational error rather than a verdict about a tree.
func TestVerifyMerkleRefusesAnAmbiguousRequest(t *testing.T) {
	t.Parallel()

	leaves := digests(2)

	_, err := verifier.VerifyMerkle(verifier.MerkleInput{})
	require.ErrorIs(t, err, verifier.ErrInvalidInput)

	_, err = verifier.VerifyMerkle(verifier.MerkleInput{Leaves: leaves, Leaf: leaves[0]})
	require.ErrorIs(t, err, verifier.ErrInvalidInput)
}

// TestVerifyMerkleDuplicatesASingleLeaf pins the rule most likely to diverge in
// an independent implementation: a tree of one leaf still folds it with itself.
func TestVerifyMerkleDuplicatesASingleLeaf(t *testing.T) {
	t.Parallel()

	leaves := digests(1)

	root, err := verifier.ComputeMerkleRoot(leaves)
	require.NoError(t, err)

	assert.NotEqual(t, hexOf(leaves[0]), hexOf(root),
		"a single leaf is not its own root under this profile")

	r, err := verifier.VerifyMerkle(verifier.MerkleInput{Leaves: leaves, Root: root})
	require.NoError(t, err)

	assert.Equal(t, report.StatusValid, statusOf(t, r, "proof_merkle.root"))
}

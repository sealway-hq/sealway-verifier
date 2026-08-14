// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package merkle_test

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealway-hq/sealway-verifier/packages/verifier/merkle"
)

// leaf returns the deterministic test leaf at the given index. The same inputs
// were fed to an independent reference implementation to produce the expected
// roots and paths below, so the vectors are not a restatement of the code they
// verify.
func leaf(i int) []byte {
	sum := sha512.Sum512([]byte("leaf-" + strconv.Itoa(i)))

	return sum[:]
}

func leaves(n int) [][]byte {
	out := make([][]byte, 0, n)
	for i := range n {
		out = append(out, leaf(i))
	}

	return out
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	require.NoError(t, err)

	return b
}

func TestComputeRootVectors(t *testing.T) {
	t.Parallel()

	// Expected roots produced by an independent reference implementation of the
	// documented profile: SHA-512 leaves, ascending order, last node duplicated
	// on an odd level, internal node SHA-512(0x01 || left || right).
	vectors := []struct {
		leafCount int
		root      string
	}{
		{1, "3ed268726b667e89f6266ce12409b66dbbd6676bb99b27bea760bc690467df882500c0002eb8e4cfbf38cb36b872933aff23b9a472820bc5948aed292e0617d3"},
		{2, "47c219a5b4bf192943231d833f9cfb62dd7c23eb20a02244e9f3fabb8b3e185948f497921feb1ff576d8e43b526dd3c2c3f840be213a0ac3536e517bef66c00d"},
		{3, "a50a3d6dae477881f852111ef6947c2385f96f1ccb6125b2d259d719aa6d459dfa5fb9302099e8bfc92af9fb56b3bc750e46363e886f1e203020889315d90280"},
		{4, "76e1c13ce6c9c1f28a87e1815dc8399bd91026a8b15e10b78d54bcfdd6d7ab12d716ef54465c1419e1aa6aa538e06a69f2309aff3870f8d3319d1dc1cc6c081d"},
		{5, "bc91bace72fafcd5de45b9f55f3f0d6f822d7550af26e1f228920d91777acd9bf6eaf63272c10c04f504f2d341035a47b4e905e0da8c9ef0d8372bd45b6b1a18"},
		{6, "a5eb8c9189eb424f7c8aa641c0825e6a1250a02b2f24aa13411a7e236c82e89888f9004e8766dc5be7c5915508bcbd7b9a15beb77a7cdd2c322c5f4effc4aeec"},
		{7, "a82a2de88dd2659b19931b85e7f17eed9fd1917936f11ce067e5bcdfe98998c7120382948ba5c2a6b55704286a8e49fe8e146a0c0c4630b141d179585deb99a1"},
		{8, "95de0882d7e039233011ebce1822b34cae2689e8b54d060ecc64ec493a1a2b786986c506f27d05f4bd6f2361ce108663c4ecd76a14d0c6812ece602983e0f5ab"},
	}

	for _, v := range vectors {
		t.Run(fmt.Sprintf("%d_leaves", v.leafCount), func(t *testing.T) {
			t.Parallel()

			root, err := merkle.ComputeRoot(leaves(v.leafCount))
			require.NoError(t, err)
			assert.Equal(t, v.root, hex.EncodeToString(root))
		})
	}
}

// TestSingleLeafIsStillHashed pins the behaviour that surprises people most: a
// one leaf tree is not the leaf itself, because the odd node strategy duplicates
// the last node of every incomplete level including the leaf level.
func TestSingleLeafIsStillHashed(t *testing.T) {
	t.Parallel()

	l := leaf(0)

	root, err := merkle.ComputeRoot([][]byte{l})
	require.NoError(t, err)
	assert.NotEqual(t, l, root)

	expected := sha512.Sum512(append(append([]byte{0x01}, l...), l...))
	assert.Equal(t, expected[:], root)
}

// TestInternalNodeUsesRawBytes guards against the classic mistake of hashing the
// hexadecimal text of a digest instead of the digest itself.
func TestInternalNodeUsesRawBytes(t *testing.T) {
	t.Parallel()

	l0, l1 := leaf(0), leaf(1)

	root, err := merkle.ComputeRoot([][]byte{l0, l1})
	require.NoError(t, err)

	raw := sha512.Sum512(append(append([]byte{0x01}, l0...), l1...))
	assert.Equal(t, raw[:], root)

	text := sha512.Sum512([]byte("\x01" + hex.EncodeToString(l0) + hex.EncodeToString(l1)))
	assert.NotEqual(t, text[:], root)
}

func TestComputeRootIsDeterministic(t *testing.T) {
	t.Parallel()

	for n := 1; n <= 9; n++ {
		first, err := merkle.ComputeRoot(leaves(n))
		require.NoError(t, err)

		second, err := merkle.ComputeRoot(leaves(n))
		require.NoError(t, err)

		assert.Equal(t, first, second)
	}
}

func TestComputeRootDependsOnOrder(t *testing.T) {
	t.Parallel()

	ordered, err := merkle.ComputeRoot([][]byte{leaf(0), leaf(1), leaf(2)})
	require.NoError(t, err)

	swapped, err := merkle.ComputeRoot([][]byte{leaf(1), leaf(0), leaf(2)})
	require.NoError(t, err)

	assert.NotEqual(t, ordered, swapped)
}

func TestComputeRootRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	_, err := merkle.ComputeRoot(nil)
	assert.ErrorIs(t, err, merkle.ErrNoLeaves)

	_, err = merkle.ComputeRoot([][]byte{})
	assert.ErrorIs(t, err, merkle.ErrNoLeaves)

	_, err = merkle.ComputeRoot([][]byte{make([]byte, 32)})
	assert.ErrorIs(t, err, merkle.ErrDigestSize)

	_, err = merkle.ComputeRoot([][]byte{leaf(0), nil})
	assert.ErrorIs(t, err, merkle.ErrDigestSize)
}

type sib struct {
	direction string
	hash      string
}

func (s sib) toSibling(t *testing.T) merkle.Sibling {
	t.Helper()

	d := merkle.Right
	if s.direction == "left" {
		d = merkle.Left
	}

	return merkle.Sibling{Direction: d, Hash: mustHex(t, s.hash)}
}

// TestVerifyProofVectors checks inclusion paths against the same independent
// reference implementation, covering left siblings, right siblings, several
// levels and the duplicated leaf of an odd tree.
func TestVerifyProofVectors(t *testing.T) {
	t.Parallel()

	vectors := []struct {
		leafCount int
		index     int
		siblings  []sib
	}{
		{1, 0, []sib{{"right", "97f5726ff7c88dfd6fea88789c5b93d3b3445f5190265e8108ab34f30d0096d06201d30a59383a7d7ed0ec28b23ee05e44b6d08faaaf0bb5e0c195f34281daa5"}}},
		{3, 0, []sib{{"right", "3d0c773ee2e90b639ddaf06a92d51e207d7f0f01bb3f4b8dff785a65edf7e7c9a1129526f9f52adeb3aa00068ad5cbbd2b7f623b1df93e667d95299031a9fc61"}, {"right", "c9e5e8af707930065143abd919eb50ce82ec71a6ba9c00e26338186089e997982f808ef227d14aacb3b6edcb1ced362c96cb353f294d2040f0221d10761b3083"}}},
		{3, 1, []sib{{"left", "97f5726ff7c88dfd6fea88789c5b93d3b3445f5190265e8108ab34f30d0096d06201d30a59383a7d7ed0ec28b23ee05e44b6d08faaaf0bb5e0c195f34281daa5"}, {"right", "c9e5e8af707930065143abd919eb50ce82ec71a6ba9c00e26338186089e997982f808ef227d14aacb3b6edcb1ced362c96cb353f294d2040f0221d10761b3083"}}},
		{3, 2, []sib{{"right", "cfbbd140e2d603eb531444d13589c629a1e7795b235a41b9cb0bf5954bac046f9cc56db7a5dd4e57f2bead27b61ff3592743dc039c48aeb65613494bcb50a36c"}, {"left", "47c219a5b4bf192943231d833f9cfb62dd7c23eb20a02244e9f3fabb8b3e185948f497921feb1ff576d8e43b526dd3c2c3f840be213a0ac3536e517bef66c00d"}}},
		{5, 0, []sib{{"right", "3d0c773ee2e90b639ddaf06a92d51e207d7f0f01bb3f4b8dff785a65edf7e7c9a1129526f9f52adeb3aa00068ad5cbbd2b7f623b1df93e667d95299031a9fc61"}, {"right", "0fc75ade4977548966194f8af0bb77636f1f013df8365f90582157b12230b447dc49ab398d87cb59f084c18c98dfd6213682ef9ef3b7d24f8f17ed3a29c3e9c2"}, {"right", "789e3b0ac8f3e15960ae21cbdae7286801c61dfa750f3ad6f4f90f427b69178a5c3041ed2adab952f365752d7f0cf8641aa6980f777513eec6cc958f3a871804"}}},
		{5, 3, []sib{{"left", "cfbbd140e2d603eb531444d13589c629a1e7795b235a41b9cb0bf5954bac046f9cc56db7a5dd4e57f2bead27b61ff3592743dc039c48aeb65613494bcb50a36c"}, {"left", "47c219a5b4bf192943231d833f9cfb62dd7c23eb20a02244e9f3fabb8b3e185948f497921feb1ff576d8e43b526dd3c2c3f840be213a0ac3536e517bef66c00d"}, {"right", "789e3b0ac8f3e15960ae21cbdae7286801c61dfa750f3ad6f4f90f427b69178a5c3041ed2adab952f365752d7f0cf8641aa6980f777513eec6cc958f3a871804"}}},
		{5, 4, []sib{{"right", "e07301521b743e67187938966fccc65afeb121e16c95462d4ea73df97c6a0cb1748dd69c610bb87e2a2633ae5a7b39765bc0011fbb7b6dcb3ff2a3f38df35f01"}, {"right", "78f5ea561d3137068275e73c2494af967f92e871b4d6b3cf80754ffcc9a8336dbefdfd9d3fe1bf78ade01a07a54b850d7f6faae52b83278134e6fbcaaf14c00d"}, {"left", "76e1c13ce6c9c1f28a87e1815dc8399bd91026a8b15e10b78d54bcfdd6d7ab12d716ef54465c1419e1aa6aa538e06a69f2309aff3870f8d3319d1dc1cc6c081d"}}},
	}

	for _, v := range vectors {
		t.Run(fmt.Sprintf("%d_leaves_index_%d", v.leafCount, v.index), func(t *testing.T) {
			t.Parallel()

			root, err := merkle.ComputeRoot(leaves(v.leafCount))
			require.NoError(t, err)

			siblings := make([]merkle.Sibling, 0, len(v.siblings))
			for _, s := range v.siblings {
				siblings = append(siblings, s.toSibling(t))
			}

			ok, err := merkle.VerifyProof(leaf(v.index), siblings, root)
			require.NoError(t, err)
			assert.True(t, ok)
		})
	}
}

// TestGenerateProofRoundTrip checks that a generated path verifies for every
// leaf of every tree size, which also exercises the odd node strategy at every
// level.
func TestGenerateProofRoundTrip(t *testing.T) {
	t.Parallel()

	for n := 1; n <= 17; n++ {
		t.Run(fmt.Sprintf("%d_leaves", n), func(t *testing.T) {
			t.Parallel()

			ls := leaves(n)

			for i := range n {
				siblings, root, err := merkle.GenerateProof(ls, i)
				require.NoError(t, err)
				require.Len(t, siblings, merkle.Depth(n))

				ok, err := merkle.VerifyProof(ls[i], siblings, root)
				require.NoError(t, err)
				assert.True(t, ok, "leaf %d of %d", i, n)
			}
		})
	}
}

func TestGenerateProofRejectsBadIndex(t *testing.T) {
	t.Parallel()

	_, _, err := merkle.GenerateProof(leaves(3), 3)
	assert.ErrorIs(t, err, merkle.ErrIndexOutOfRange)

	_, _, err = merkle.GenerateProof(leaves(3), -1)
	assert.ErrorIs(t, err, merkle.ErrIndexOutOfRange)
}

func TestVerifyProofRejectsTamperedPaths(t *testing.T) {
	t.Parallel()

	ls := leaves(5)

	siblings, root, err := merkle.GenerateProof(ls, 2)
	require.NoError(t, err)

	t.Run("wrong leaf", func(t *testing.T) {
		t.Parallel()

		ok, err := merkle.VerifyProof(ls[3], siblings, root)
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("wrong root", func(t *testing.T) {
		t.Parallel()

		other, err := merkle.ComputeRoot(leaves(6))
		require.NoError(t, err)

		ok, err := merkle.VerifyProof(ls[2], siblings, other)
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("wrong direction", func(t *testing.T) {
		t.Parallel()

		flipped := make([]merkle.Sibling, len(siblings))
		copy(flipped, siblings)
		flipped[0].Direction = 1 - flipped[0].Direction

		ok, err := merkle.VerifyProof(ls[2], flipped, root)
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("invalid sibling value", func(t *testing.T) {
		t.Parallel()

		tampered := make([]merkle.Sibling, len(siblings))
		copy(tampered, siblings)
		tampered[1].Hash = bytes.Repeat([]byte{0xaa}, merkle.DigestSize)

		ok, err := merkle.VerifyProof(ls[2], tampered, root)
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("truncated path", func(t *testing.T) {
		t.Parallel()

		ok, err := merkle.VerifyProof(ls[2], siblings[:1], root)
		require.NoError(t, err)
		assert.False(t, ok)
	})
}

func TestVerifyProofRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	ls := leaves(4)

	siblings, root, err := merkle.GenerateProof(ls, 0)
	require.NoError(t, err)

	t.Run("short leaf", func(t *testing.T) {
		t.Parallel()

		_, err := merkle.VerifyProof(make([]byte, 16), siblings, root)
		assert.ErrorIs(t, err, merkle.ErrDigestSize)
	})

	t.Run("short root", func(t *testing.T) {
		t.Parallel()

		_, err := merkle.VerifyProof(ls[0], siblings, make([]byte, 16))
		assert.ErrorIs(t, err, merkle.ErrDigestSize)
	})

	t.Run("short sibling", func(t *testing.T) {
		t.Parallel()

		bad := []merkle.Sibling{{Direction: merkle.Right, Hash: make([]byte, 8)}}

		_, err := merkle.VerifyProof(ls[0], bad, root)
		assert.ErrorIs(t, err, merkle.ErrDigestSize)
	})

	t.Run("invalid direction", func(t *testing.T) {
		t.Parallel()

		bad := []merkle.Sibling{{Direction: merkle.Direction(7), Hash: leaf(1)}}

		_, err := merkle.VerifyProof(ls[0], bad, root)
		assert.ErrorIs(t, err, merkle.ErrInvalidDirection)
	})

	t.Run("path too deep", func(t *testing.T) {
		t.Parallel()

		deep := make([]merkle.Sibling, merkle.MaxSiblings+1)
		for i := range deep {
			deep[i] = merkle.Sibling{Direction: merkle.Right, Hash: leaf(i)}
		}

		_, err := merkle.VerifyProof(ls[0], deep, root)
		assert.ErrorIs(t, err, merkle.ErrTooManySiblings)
	})
}

func TestRootFromProofReturnsRecomputedValue(t *testing.T) {
	t.Parallel()

	ls := leaves(3)

	siblings, root, err := merkle.GenerateProof(ls, 1)
	require.NoError(t, err)

	computed, err := merkle.RootFromProof(ls[1], siblings)
	require.NoError(t, err)
	assert.Equal(t, root, computed)

	// A path that does not belong to the leaf still recomputes to something; it
	// simply is not the root.
	other, err := merkle.RootFromProof(ls[2], siblings)
	require.NoError(t, err)
	assert.NotEqual(t, root, other)
}

func TestDepth(t *testing.T) {
	t.Parallel()

	assert.Equal(t, 0, merkle.Depth(0))
	assert.Equal(t, 1, merkle.Depth(1))
	assert.Equal(t, 1, merkle.Depth(2))
	assert.Equal(t, 2, merkle.Depth(3))
	assert.Equal(t, 2, merkle.Depth(4))
	assert.Equal(t, 3, merkle.Depth(5))
	assert.Equal(t, 3, merkle.Depth(8))
	assert.Equal(t, 4, merkle.Depth(9))
	assert.Equal(t, 4, merkle.Depth(16))
	assert.Equal(t, 5, merkle.Depth(17))
}

func TestDirectionString(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "left", merkle.Left.String())
	assert.Equal(t, "right", merkle.Right.String())
	assert.Equal(t, "unknown", merkle.Direction(9).String())
}

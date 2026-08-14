// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

// Package merkle exposes the Merkle operations of the public Sealway proof
// format.
//
// The cryptographic profile is:
//
//	hash algorithm      SHA-512
//	leaf                SHA-512(raw file bytes)
//	leaf ordering       ascending certified item position
//	odd node strategy   duplicate the last node of the level
//	internal node       SHA-512(0x01 || left || right)
//
// The left and right operands of an internal node are the raw 64 byte digests,
// never their ASCII hexadecimal representation.
//
// The tree construction itself is delegated to github.com/hyperscale-stack/merkle;
// this package is the verifier facing surface over it, adding the strict input
// validation an untrusted proof requires. Its operations are pure functions
// with no filesystem, network or global state, so they can be reused unchanged
// by a WebAssembly build.
package merkle

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	hsmerkle "github.com/hyperscale-stack/merkle"
)

// DigestSize is the length in bytes of every hash handled by this package.
const DigestSize = 64

// MaxSiblings bounds the depth of an inclusion path accepted by VerifyProof. A
// SHA-512 tree deeper than this cannot be built from any realistic leaf count.
const MaxSiblings = 64

// InternalNodePrefix is prepended to the concatenation of two child digests
// before hashing an internal node. It separates the leaf domain from the
// internal node domain and defeats second preimage attacks on the tree.
const InternalNodePrefix byte = 0x01

// Errors returned by this package. They describe malformed inputs; a proof that
// is well formed but simply does not verify is reported through the boolean
// result of VerifyProof rather than through an error.
var (
	// ErrNoLeaves is returned when a tree is requested for an empty leaf set.
	ErrNoLeaves = errors.New("merkle: at least one leaf is required")
	// ErrDigestSize is returned when a digest does not have the expected length.
	ErrDigestSize = errors.New("merkle: digest must be 64 bytes")
	// ErrTooManySiblings is returned when an inclusion path is implausibly deep.
	ErrTooManySiblings = errors.New("merkle: inclusion path is too deep")
	// ErrIndexOutOfRange is returned when a leaf index does not address a leaf.
	ErrIndexOutOfRange = errors.New("merkle: leaf index is out of range")
	// ErrInvalidDirection is returned for a sibling direction that is neither
	// left nor right.
	ErrInvalidDirection = errors.New("merkle: invalid sibling direction")
)

// Direction indicates on which side of the current node a sibling sits.
type Direction uint8

const (
	// Left means the sibling is combined to the left of the current node, that
	// is SHA-512(0x01 || sibling || current).
	Left Direction = iota
	// Right means the sibling is combined to the right of the current node, that
	// is SHA-512(0x01 || current || sibling).
	Right
)

// String implements fmt.Stringer.
func (d Direction) String() string {
	switch d {
	case Left:
		return "left"
	case Right:
		return "right"
	default:
		return "unknown"
	}
}

// Sibling is one step of an inclusion path.
type Sibling struct {
	Direction Direction
	Hash      []byte
}

// ComputeRoot builds the Sealway proof Merkle tree over the given leaves and
// returns its root.
//
// Leaves must already be SHA-512 digests and must be supplied in ascending
// certified item position order. A single leaf still produces a root of
// SHA-512(0x01 || leaf || leaf), because the odd node strategy duplicates the
// last node of every incomplete level, including the leaf level.
func ComputeRoot(leaves [][]byte) ([]byte, error) {
	if err := checkLeaves(leaves); err != nil {
		return nil, err
	}

	tree := hsmerkle.New(context.Background(), leaves, hsmerkle.WithHashType(hsmerkle.HashTypeSHA512))
	if tree == nil {
		return nil, ErrNoLeaves
	}

	root := tree.RootHash()
	if len(root) != DigestSize {
		return nil, fmt.Errorf("merkle: unexpected root length %d", len(root))
	}

	return root, nil
}

// GenerateProof builds the tree over the given leaves and returns the inclusion
// path of the leaf at the given index, together with the resulting root.
//
// It backs the standalone Merkle tools that the public Sealway website will
// expose; the verifier itself only ever verifies paths it did not generate.
func GenerateProof(leaves [][]byte, index int) (siblings []Sibling, root []byte, err error) {
	if err := checkLeaves(leaves); err != nil {
		return nil, nil, err
	}

	if index < 0 || index >= len(leaves) {
		return nil, nil, fmt.Errorf("%w: %d of %d leaves", ErrIndexOutOfRange, index, len(leaves))
	}

	tree := hsmerkle.New(context.Background(), leaves, hsmerkle.WithHashType(hsmerkle.HashTypeSHA512))
	if tree == nil {
		return nil, nil, ErrNoLeaves
	}

	p := tree.GenerateProof(uint32(index)) //nolint:gosec // index is bounds checked above
	if p == nil {
		return nil, nil, fmt.Errorf("%w: %d of %d leaves", ErrIndexOutOfRange, index, len(leaves))
	}

	siblings = make([]Sibling, 0, len(p.Siblings))
	for _, s := range p.Siblings {
		d := Right
		if s.Direction == hsmerkle.Left {
			d = Left
		}

		siblings = append(siblings, Sibling{Direction: d, Hash: s.Hash})
	}

	return siblings, tree.RootHash(), nil
}

// RootFromProof recomputes the root reachable from a leaf through an inclusion
// path.
//
// It does not compare the result with anything: use VerifyProof to decide
// whether a path proves inclusion in a given root.
func RootFromProof(leaf []byte, siblings []Sibling) ([]byte, error) {
	if len(leaf) != DigestSize {
		return nil, fmt.Errorf("%w: leaf has %d bytes", ErrDigestSize, len(leaf))
	}

	if len(siblings) > MaxSiblings {
		return nil, fmt.Errorf("%w: %d siblings", ErrTooManySiblings, len(siblings))
	}

	proof, err := toProof(siblings)
	if err != nil {
		return nil, err
	}

	// The upstream Proof only exposes a boolean verification against a known
	// root, so the path is walked here with the exact same rule in order to be
	// able to report the recomputed value.
	current := leaf

	for _, s := range proof.Siblings {
		combined := make([]byte, 0, 1+len(current)+len(s.Hash))
		combined = append(combined, InternalNodePrefix)

		if s.Direction == hsmerkle.Left {
			combined = append(combined, s.Hash...)
			combined = append(combined, current...)
		} else {
			combined = append(combined, current...)
			combined = append(combined, s.Hash...)
		}

		current = hsmerkle.SHA512(combined)
	}

	return current, nil
}

// VerifyProof reports whether the inclusion path proves that the leaf belongs to
// the tree with the given root.
//
// An error is returned only for a malformed input. A well formed path that does
// not reconstruct the root returns false with a nil error.
func VerifyProof(leaf []byte, siblings []Sibling, root []byte) (bool, error) {
	if len(root) != DigestSize {
		return false, fmt.Errorf("%w: root has %d bytes", ErrDigestSize, len(root))
	}

	computed, err := RootFromProof(leaf, siblings)
	if err != nil {
		return false, err
	}

	proof, err := toProof(siblings)
	if err != nil {
		return false, err
	}

	// Cross-check the locally walked path against the upstream implementation so
	// that the two can never silently diverge.
	upstream := proof.Verify(leaf, root)
	local := bytes.Equal(computed, root)

	if upstream != local {
		return false, errors.New("merkle: inconsistent proof verification")
	}

	return local, nil
}

// Depth returns the number of inclusion path steps of a tree with the given
// number of leaves.
func Depth(leafCount int) int {
	if leafCount <= 0 {
		return 0
	}

	depth := 1
	nodes := (leafCount + 1) / 2

	for nodes > 1 {
		nodes = (nodes + 1) / 2
		depth++
	}

	return depth
}

func toProof(siblings []Sibling) (*hsmerkle.Proof, error) {
	out := make([]hsmerkle.Sibling, 0, len(siblings))

	for i, s := range siblings {
		if len(s.Hash) != DigestSize {
			return nil, fmt.Errorf("%w: sibling %d has %d bytes", ErrDigestSize, i, len(s.Hash))
		}

		switch s.Direction {
		case Left:
			out = append(out, hsmerkle.Sibling{Direction: hsmerkle.Left, Hash: s.Hash})
		case Right:
			out = append(out, hsmerkle.Sibling{Direction: hsmerkle.Right, Hash: s.Hash})
		default:
			return nil, fmt.Errorf("%w: sibling %d has direction %d", ErrInvalidDirection, i, s.Direction)
		}
	}

	return &hsmerkle.Proof{Siblings: out, HashType: hsmerkle.HashTypeSHA512}, nil
}

func checkLeaves(leaves [][]byte) error {
	if len(leaves) == 0 {
		return ErrNoLeaves
	}

	for i, l := range leaves {
		if len(l) != DigestSize {
			return fmt.Errorf("%w: leaf %d has %d bytes", ErrDigestSize, i, len(l))
		}
	}

	return nil
}

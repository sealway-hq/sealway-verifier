// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package verifier

import (
	"context"
	"fmt"
	"strconv"

	"github.com/sealway-hq/sealway-verifier/packages/verifier/merkle"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/proof"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/report"
)

const sectionMerkleTitle = "Proof Merkle tree"

// verifyProofMerkle rebuilds the proof Merkle tree and verifies the individual
// inclusion paths.
//
// When every original file was supplied and verified, the tree is rebuilt from
// the recomputed source digests, so the certified root is derived from the files
// themselves rather than from data the manifest merely asserts. When the files
// are missing, that step is skipped and only the internal consistency of the
// certified data is established.
func (r *run) verifyProofMerkle(ctx context.Context) {
	reportProgress(r.opts.progress, Progress{Stage: StageMerkle})

	items := r.manifest.ItemsByPosition()
	expected := r.manifest.Proof.MerkleRoot

	if err := ctx.Err(); err != nil {
		r.builder.Add(report.SectionProofMerkle, sectionMerkleTitle,
			report.NewSkipped("proof_merkle.root", "Merkle root",
				"Verification was cancelled: "+err.Error()))

		return
	}

	r.checkLeafHashes(items)
	r.checkRebuiltRoot(items, expected)
	r.checkCertifiedRoot(items, expected)
	r.checkItemProofs(items, expected)
}

// checkLeafHashes reports whether the certified leaves are backed by recomputed
// source digests.
func (r *run) checkLeafHashes(items []proof.Item) {
	const (
		id    = "proof_merkle.leaf_hashes"
		title = "Leaf hashes"
	)

	leaves, complete := r.verifiedLeaves(items)
	if complete {
		r.builder.Add(report.SectionProofMerkle, sectionMerkleTitle,
			report.NewValid(id, title, fmt.Sprintf(
				"All %d Merkle leaves were recomputed from the original files: every leaf is the "+
					"SHA-512 of the raw bytes of its file.", len(leaves))))

		return
	}

	r.builder.Add(report.SectionProofMerkle, sectionMerkleTitle,
		report.NewSkipped(id, title,
			"The Merkle leaves could not all be recomputed from the original files, because some "+
				"files were not provided or did not match their certified leaf. The leaves used below "+
				"are the ones certified by the manifest."))
}

// checkRebuiltRoot rebuilds the tree from the verified source digests.
func (r *run) checkRebuiltRoot(items []proof.Item, expected proof.Hash) {
	const (
		id    = "proof_merkle.root"
		title = "Merkle root"
	)

	leaves, complete := r.verifiedLeaves(items)
	if !complete {
		r.builder.Add(report.SectionProofMerkle, sectionMerkleTitle,
			report.NewSkipped(id, title,
				"The proof Merkle tree could not be rebuilt from the original files, because they were "+
					"not all provided and verified. Rebuilding it from the certified leaf hashes "+
					"instead would only restate what the manifest already claims."))

		return
	}

	computed, err := merkle.ComputeRoot(leaves)
	if err != nil {
		r.builder.Add(report.SectionProofMerkle, sectionMerkleTitle,
			report.NewInvalid(id, title, "The proof Merkle tree could not be rebuilt: "+err.Error()))

		return
	}

	if !expected.Equal(computed) {
		r.builder.Add(report.SectionProofMerkle, sectionMerkleTitle,
			report.NewInvalid(id, title,
				"The Merkle root rebuilt from the original files does not match the certified proof "+
					"root.").
				WithDetails(map[string]string{
					"expected": expected.String(),
					"computed": proof.Hash(computed).String(),
				}))

		return
	}

	r.builder.Add(report.SectionProofMerkle, sectionMerkleTitle,
		report.NewValid(id, title, fmt.Sprintf(
			"The Merkle root rebuilt from the %d original file(s) matches the certified proof root "+
				"byte for byte.", len(leaves))).
			WithDetail("merkle_root", expected.String()))
}

// checkCertifiedRoot rebuilds the tree from the certified leaves.
//
// This establishes that the manifest is internally consistent. It proves nothing
// about the original files: it only shows that the leaves the manifest declares
// really do produce the root it declares.
func (r *run) checkCertifiedRoot(items []proof.Item, expected proof.Hash) {
	const (
		id    = "proof_merkle.certified_root"
		title = "Certified proof root consistency"
	)

	leaves := make([][]byte, 0, len(items))
	for _, it := range items {
		leaves = append(leaves, it.LeafHash.Bytes())
	}

	computed, err := merkle.ComputeRoot(leaves)
	if err != nil {
		r.builder.Add(report.SectionProofMerkle, sectionMerkleTitle,
			report.NewInvalid(id, title,
				"The certified leaf hashes do not form a well formed Merkle tree: "+err.Error()))

		return
	}

	if !expected.Equal(computed) {
		r.builder.Add(report.SectionProofMerkle, sectionMerkleTitle,
			report.NewInvalid(id, title,
				"The certified leaf hashes do not reconstruct the certified proof root: the manifest "+
					"contradicts itself.").
				WithDetails(map[string]string{
					"expected": expected.String(),
					"computed": proof.Hash(computed).String(),
				}))

		return
	}

	r.builder.Add(report.SectionProofMerkle, sectionMerkleTitle,
		report.NewValid(id, title, fmt.Sprintf(
			"The %d certified leaf hash(es) reconstruct the certified proof root. This shows the "+
				"manifest is internally consistent; it does not prove anything about files that were "+
				"not provided.", len(leaves))))
}

// checkItemProofs verifies the individual inclusion path of every certified
// item.
func (r *run) checkItemProofs(items []proof.Item, expected proof.Hash) {
	const (
		id    = "proof_merkle.item_proofs"
		title = "Individual inclusion proofs"
	)

	var (
		present  int
		verified int
		failures []string
	)

	for _, it := range items {
		if it.MerkleProof == nil {
			continue
		}

		present++

		leaf, fromSource := r.leafForProof(it)

		ok, err := verifyItemProof(leaf, it.MerkleProof, expected)

		switch {
		case err != nil:
			failures = append(failures, fmt.Sprintf("item %d: %s", it.Position, err))
		case !ok:
			failures = append(failures, fmt.Sprintf(
				"item %d: the inclusion path does not reconstruct the certified proof root", it.Position))
		default:
			verified++
			_ = fromSource
		}
	}

	switch {
	case present == 0:
		r.builder.Add(report.SectionProofMerkle, sectionMerkleTitle,
			report.NewSkipped(id, title,
				"The manifest carries no individual inclusion proof, so none could be verified."))
	case len(failures) > 0:
		r.builder.Add(report.SectionProofMerkle, sectionMerkleTitle,
			report.NewInvalid(id, title, fmt.Sprintf(
				"%d of %d individual inclusion proof(s) failed.", len(failures), present)).
				WithDetails(indexed("failure", failures)))
	default:
		r.builder.Add(report.SectionProofMerkle, sectionMerkleTitle,
			report.NewValid(id, title, r.itemProofsMessage(items, verified)).
				WithDetail("verified", strconv.Itoa(verified)))
	}
}

func (r *run) itemProofsMessage(items []proof.Item, verified int) string {
	if _, complete := r.verifiedLeaves(items); complete {
		return fmt.Sprintf(
			"All %d individual inclusion proof(s) reconstruct the certified proof root from the "+
				"SHA-512 recomputed from the original files.", verified)
	}

	return fmt.Sprintf(
		"All %d individual inclusion proof(s) reconstruct the certified proof root from the "+
			"certified leaf hashes. Because the original files were not provided, this shows the "+
			"certified data is internally consistent; it is not evidence that any missing file "+
			"matches its certified hash.", verified)
}

// leafForProof returns the leaf an inclusion path should start from.
//
// A digest recomputed from the original file is preferred, because verifying a
// path from it links the file itself to the certified root. Falling back to the
// certified leaf only establishes internal consistency, and the report says so.
func (r *run) leafForProof(it proof.Item) (leaf []byte, fromSource bool) {
	if r.matches != nil {
		if m, ok := r.matches.byPosition[it.Position]; ok && m.err == nil && equalHash(m.hash, it.LeafHash) {
			return m.hash, true
		}
	}

	return it.LeafHash.Bytes(), false
}

func verifyItemProof(leaf []byte, p *proof.MerkleProof, root proof.Hash) (bool, error) {
	siblings, err := toMerkleSiblings(p.Siblings)
	if err != nil {
		return false, err
	}

	return merkle.VerifyProof(leaf, siblings, root.Bytes())
}

// toMerkleSiblings converts the manifest representation of an inclusion path.
//
// An unrecognised direction is rejected rather than defaulted, so a malformed
// path can never be silently reinterpreted into a valid one.
func toMerkleSiblings(in []proof.Sibling) ([]merkle.Sibling, error) {
	out := make([]merkle.Sibling, 0, len(in))

	for i, s := range in {
		var d merkle.Direction

		switch s.Position {
		case proof.SiblingLeft:
			d = merkle.Left
		case proof.SiblingRight:
			d = merkle.Right
		default:
			return nil, fmt.Errorf("sibling %d has the invalid direction %q", i, s.Position)
		}

		out = append(out, merkle.Sibling{Direction: d, Hash: s.Hash.Bytes()})
	}

	return out, nil
}

func indexed(prefix string, values []string) map[string]string {
	out := make(map[string]string, len(values))
	for i, v := range values {
		out[prefix+"."+strconv.Itoa(i)] = v
	}

	return out
}

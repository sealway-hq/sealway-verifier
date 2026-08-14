// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package verifier

import (
	"fmt"
	"strconv"

	"github.com/sealway-hq/sealway-verifier/packages/verifier/merkle"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/proof"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/report"
)

const sectionAccumulatorTitle = "Accumulator"

// verifyAccumulator recomputes the accumulator Merkle root from the proof root
// and the inclusion path.
//
// The accumulator root declared by the manifest is never trusted because it is
// present: it is recomputed from the proof root and the inclusion path, and only
// then compared. This step needs no original file and is therefore performed
// even for a certificate supplied on its own.
func (r *run) verifyAccumulator() {
	reportProgress(r.opts.progress, Progress{Stage: StageAccumulator})

	const (
		proofID    = "accumulator.inclusion_proof"
		proofTitle = "Inclusion proof"

		rootID    = "accumulator.root"
		rootTitle = "Accumulator Merkle root"
	)

	n := &r.manifest.Notarization
	proofRoot := r.manifest.Proof.MerkleRoot
	expected := n.AccumulatorRoot

	if n.InclusionProof == nil {
		reason := "The manifest carries no accumulator inclusion proof, so the accumulator root " +
			"cannot be recomputed from the proof root."

		r.builder.Add(report.SectionAccumulator, sectionAccumulatorTitle,
			report.NewSkipped(proofID, proofTitle, reason),
			report.NewSkipped(rootID, rootTitle, reason))

		return
	}

	if proofRoot.IsZero() || expected.IsZero() {
		reason := "The manifest does not declare both a proof Merkle root and an accumulator " +
			"Merkle root, so the inclusion of one in the other cannot be verified."

		r.builder.Add(report.SectionAccumulator, sectionAccumulatorTitle,
			report.NewSkipped(proofID, proofTitle, reason),
			report.NewSkipped(rootID, rootTitle, reason))

		return
	}

	siblings, err := toMerkleSiblings(n.InclusionProof.Siblings)
	if err != nil {
		r.builder.Add(report.SectionAccumulator, sectionAccumulatorTitle,
			report.NewInvalid(proofID, proofTitle,
				"The accumulator inclusion proof is malformed: "+err.Error()),
			report.NewSkipped(rootID, rootTitle,
				"The accumulator root could not be recomputed because the inclusion proof is malformed."))

		return
	}

	computed, err := merkle.RootFromProof(proofRoot.Bytes(), siblings)
	if err != nil {
		r.builder.Add(report.SectionAccumulator, sectionAccumulatorTitle,
			report.NewInvalid(proofID, proofTitle,
				"The accumulator inclusion proof could not be evaluated: "+err.Error()),
			report.NewSkipped(rootID, rootTitle,
				"The accumulator root could not be recomputed."))

		return
	}

	details := map[string]string{
		"proof_root": proofRoot.String(),
		"expected":   expected.String(),
		"computed":   proof.Hash(computed).String(),
		"leaf_index": strconv.Itoa(n.InclusionProof.LeafIndex),
		"depth":      strconv.Itoa(len(siblings)),
	}

	if !expected.Equal(computed) {
		r.builder.Add(report.SectionAccumulator, sectionAccumulatorTitle,
			report.NewInvalid(proofID, proofTitle,
				"Walking the inclusion path from the proof Merkle root does not reach the certified "+
					"accumulator root.").
				WithDetails(details),
			report.NewInvalid(rootID, rootTitle,
				"The recomputed accumulator Merkle root does not match the one certified by the "+
					"manifest.").
				WithDetails(details))

		return
	}

	r.builder.Add(report.SectionAccumulator, sectionAccumulatorTitle,
		report.NewValid(proofID, proofTitle, fmt.Sprintf(
			"The inclusion path of %d step(s) reaches the certified accumulator root from the proof "+
				"Merkle root at leaf index %d.", len(siblings), n.InclusionProof.LeafIndex)).
			WithDetails(details),
		report.NewValid(rootID, rootTitle,
			"The recomputed accumulator Merkle root matches the one certified by the manifest byte "+
				"for byte: the proof root is included in that accumulator.").
			WithDetails(details))
}

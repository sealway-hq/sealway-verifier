// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package verifier_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealway-hq/sealway-verifier/internal/prooftest"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/report"
)

// TestAccumulatorStageWithoutInclusionProof covers a manifest that declares an
// accumulator root but no path to it. The root is not trusted merely because it
// is present, so the step is skipped rather than accepted.
func TestAccumulatorStageWithoutInclusionProof(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{
		Files: prooftest.DefaultFiles(1),
		MutateManifest: func(m map[string]any) {
			delete(m["notarization"].(map[string]any), "inclusion_proof")
		},
	})

	r, err := offline().VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), nil)
	require.NoError(t, err)

	assert.Equal(t, report.StatusSkipped, statusOf(t, r, "accumulator.inclusion_proof"))
	assert.Equal(t, report.StatusSkipped, statusOf(t, r, "accumulator.root"))

	c, _ := r.Check("accumulator.inclusion_proof")
	assert.Contains(t, c.Message, "no accumulator inclusion proof")
}

// TestAccumulatorStageWithMalformedPath covers an inclusion path whose sibling
// direction is not a direction at all. It is rejected rather than defaulted to
// one side.
func TestAccumulatorStageWithMalformedPath(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{
		Files: prooftest.DefaultFiles(1),
		MutateManifest: func(m map[string]any) {
			path := m["notarization"].(map[string]any)["inclusion_proof"].(map[string]any)
			path["siblings"].([]any)[0].(map[string]any)["position"] = "sideways"
		},
	})

	r, err := offline().VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), nil)
	require.NoError(t, err)

	assert.Equal(t, report.ResultInvalid, r.Result)
	assert.Equal(t, report.StatusInvalid, statusOf(t, r, "accumulator.inclusion_proof"))
	assert.Equal(t, report.StatusSkipped, statusOf(t, r, "accumulator.root"))

	// The manifest structure check catches it too, and says which field.
	c, _ := r.Check("certificate.manifest_schema")
	assert.Equal(t, report.StatusInvalid, c.Status)
}

// TestAccumulatorStageWithoutRoots covers a manifest that declares neither root,
// which leaves nothing to relate.
func TestAccumulatorStageWithoutRoots(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{
		Files: prooftest.DefaultFiles(1),
		MutateManifest: func(m map[string]any) {
			delete(m["notarization"].(map[string]any), "accumulator_root")
		},
	})

	r, err := offline().VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), nil)
	require.NoError(t, err)

	assert.Equal(t, report.StatusSkipped, statusOf(t, r, "accumulator.inclusion_proof"))
	assert.Equal(t, report.StatusSkipped, statusOf(t, r, "accumulator.root"))
}

// TestAccumulatorDetailsExposeBothRoots checks the report carries enough context
// for a reader to redo the comparison by hand.
func TestAccumulatorDetailsExposeBothRoots(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	r, err := offline().VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), nil)
	require.NoError(t, err)

	c, ok := r.Check("accumulator.root")
	require.True(t, ok)
	assert.Equal(t, report.StatusValid, c.Status)
	assert.Equal(t, hexOf(p.MerkleRoot), c.Details["proof_root"])
	assert.Equal(t, hexOf(p.AccumulatorRoot), c.Details["expected"])
	assert.Equal(t, hexOf(p.AccumulatorRoot), c.Details["computed"])
	assert.Equal(t, "0", c.Details["leaf_index"])
}

// TestItemWithoutInclusionProofSkipsTheCheck records that an absent individual
// path is not a structural error: it simply cannot be verified.
func TestItemWithoutInclusionProofSkipsTheCheck(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{
		Files: prooftest.DefaultFiles(2),
		MutateManifest: func(m map[string]any) {
			for _, item := range m["items"].([]any) {
				delete(item.(map[string]any), "merkle_proof")
			}
		},
	})

	r, err := offline().VerifyCertificate(t.Context(),
		bytes.NewReader(p.Certificate), sourcesFor(p.Files))
	require.NoError(t, err)

	assert.Equal(t, report.StatusSkipped, statusOf(t, r, "proof_merkle.item_proofs"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "proof_merkle.root"))
	assert.Equal(t, report.ResultPartialValid, r.Result)
}

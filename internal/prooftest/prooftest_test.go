// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package prooftest_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sealway-hq/sealway-verifier/internal/prooftest"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/pdf"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/proof"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/timestamp"
)

// TestGeneratedProofIsWellFormed guards the generator itself: if it stopped
// producing valid artifacts, every test relying on it would silently become
// meaningless.
func TestGeneratedProofIsWellFormed(t *testing.T) {
	t.Parallel()

	p, err := prooftest.New(prooftest.Options{Files: prooftest.DefaultFiles(3)})
	require.NoError(t, err)

	cert, err := pdf.Open(bytes.NewReader(p.Certificate), pdf.Limits{})
	require.NoError(t, err)
	require.Equal(t, p.Manifest, cert.Manifest)
	require.Equal(t, p.Token, cert.Timestamp)

	m, err := proof.ParseBytes(cert.Manifest)
	require.NoError(t, err)
	require.NoError(t, m.Validate())
	require.True(t, m.Proof.MerkleRoot.Equal(p.MerkleRoot))
	require.True(t, m.Notarization.AccumulatorRoot.Equal(p.AccumulatorRoot))

	token, err := timestamp.Parse(cert.Timestamp)
	require.NoError(t, err)
	require.NoError(t, token.VerifySignature())
	require.True(t, token.VerifyImprint(p.MerkleRoot))
	require.True(t, token.HasTimestampingUsage())
	require.NoError(t, token.VerifyChain(p.TSA.RootPool()))
}

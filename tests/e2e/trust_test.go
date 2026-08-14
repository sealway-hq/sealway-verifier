// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package e2e_test

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealway-hq/sealway-verifier/internal/prooftest"
	"github.com/sealway-hq/sealway-verifier/packages/verifier"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/report"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/trust"
)

// Facts about the trust material stored alongside the production fixture. They
// are the real European publications, kept compressed, and asserted here so that
// a replacement is a deliberate and reviewable change.
const (
	fixtureTSAProvider  = "Lleidanet PKI S.L."
	fixtureTSATerritory = "ES"
)

// trustSnapshot reads the stored European Trusted Lists.
//
// They are the documents the European Commission and the Spanish scheme operator
// actually published, so the end-to-end suite establishes qualified status
// against real material rather than against something generated to agree with
// the verifier.
func trustSnapshot(t *testing.T) trust.Provider {
	t.Helper()

	lotl := gunzip(t, filepath.Join("..", "..", "testdata", "trust", "eu-lotl.xml.gz"))
	list := gunzip(t, filepath.Join("..", "..", "testdata", "trust", "es-trusted-list.xml.gz"))

	files, err := prooftest.SnapshotFiles(lotl, map[string][]byte{"ES": list})
	require.NoError(t, err)

	mapFS := fstest.MapFS{}
	for name, data := range files {
		mapFS[name] = &fstest.MapFile{Data: data}
	}

	return trust.NewSnapshot(mapFS, "the stored European Trusted Lists")
}

func gunzip(t *testing.T, path string) []byte {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Skipf("the stored trust material is not available: %v", err)
	}

	defer func() { _ = f.Close() }()

	zr, err := gzip.NewReader(f)
	require.NoError(t, err)

	defer func() { _ = zr.Close() }()

	data, err := io.ReadAll(zr)
	require.NoError(t, err)

	return data
}

// TestProductionTimestampIsQualified is the end-to-end answer to the question
// the whole trust subsystem exists for, on the real proof and the real lists.
func TestProductionTimestampIsQualified(t *testing.T) {
	t.Parallel()

	archive := fixtureBytes(t)

	v := verifier.New(
		verifier.WithOffline(),
		verifier.WithTrustProvider(trustSnapshot(t)),
	)

	r, err := v.VerifyBundle(t.Context(), bytes.NewReader(archive), int64(len(archive)))
	require.NoError(t, err)

	assert.Equal(t, report.StatusValid, statusOf(t, r, "timestamp.qualified"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "timestamp.trust_chain"))

	c, ok := r.Check("timestamp.qualified")
	require.True(t, ok)

	assert.Equal(t, "qualified", c.Details["determination"])
	assert.Equal(t, "QTST", c.Details["service_type"])
	assert.Equal(t, "granted", c.Details["service_status"])
	assert.Equal(t, fixtureTSATerritory, c.Details["trust_list"])
	assert.Equal(t, fixtureTSAProvider, c.Details["provider"])

	// The determination is made at the instant the token asserts, not at the
	// moment the test runs.
	assert.Equal(t, "2026-08-14T08:30:27Z", c.Details["validation_time"])
}

// TestProductionTrustListEntriesDisagree records a real property of the Spanish
// list: on 2026-08-06 the entry naming the signing unit was withdrawn while a
// new entry naming the issuing authority was granted.
//
// A verifier matching only the signing certificate would call this timestamp not
// qualified. Matching the certification path finds the entry that actually
// covers it, and the disagreement is reported rather than hidden.
func TestProductionTrustListEntriesDisagree(t *testing.T) {
	t.Parallel()

	archive := fixtureBytes(t)

	v := verifier.New(
		verifier.WithOffline(),
		verifier.WithTrustProvider(trustSnapshot(t)),
	)

	r, err := v.VerifyBundle(t.Context(), bytes.NewReader(archive), int64(len(archive)))
	require.NoError(t, err)

	c, ok := r.Check("timestamp.qualified")
	require.True(t, ok)

	conflicts, reported := c.Details["conflicting_entries"]
	require.True(t, reported, "the disagreement between entries must be surfaced")

	assert.Contains(t, conflicts, "withdrawn")
	assert.Contains(t, conflicts, "granted")

	// The path matched the issuing authority, not the signing certificate.
	path, ok := r.Check("timestamp.trust_chain")
	require.True(t, ok)
	assert.Equal(t, "issuer", path.Details["matched_by"])
	assert.Equal(t, "1", path.Details["path_length"])
}

// TestProductionQualifiedStatusNeedsTheTrustedLists checks that without the
// lists the question is left open, and that leaving it open never reads as a
// complete verification.
func TestProductionQualifiedStatusNeedsTheTrustedLists(t *testing.T) {
	t.Parallel()

	archive := fixtureBytes(t)

	r, err := verifier.New(verifier.WithOffline()).
		VerifyBundle(t.Context(), bytes.NewReader(archive), int64(len(archive)))
	require.NoError(t, err)

	assert.Equal(t, report.StatusIndeterminate, statusOf(t, r, "timestamp.qualified"))
	assert.NotEqual(t, report.ResultCompleteValid, r.Result)

	// Everything that does not depend on the lists is unaffected.
	assert.Equal(t, report.StatusValid, statusOf(t, r, "timestamp.imprint"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "proof_merkle.root"))
	assert.Zero(t, r.Summary.Invalid)
}

// TestStoredTrustMaterialIsTheOfficialPublication pins what the stored lists
// are, so that replacing them is a visible change rather than a silent one.
func TestStoredTrustMaterialIsTheOfficialPublication(t *testing.T) {
	t.Parallel()

	provider := trustSnapshot(t)

	material, err := provider.Material(t.Context(), trust.Request{
		ValidationTime: time.Date(2026, time.August, 14, 8, 30, 27, 0, time.UTC),
		Territory:      "ES",
	})
	require.NoError(t, err)

	assert.NotEmpty(t, material.LOTL)
	assert.Contains(t, material.Territories(), "ES")
}

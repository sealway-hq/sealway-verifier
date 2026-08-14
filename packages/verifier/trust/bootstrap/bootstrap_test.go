// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package bootstrap_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealway-hq/sealway-verifier/packages/verifier/trust/bootstrap"
)

// TestShippedAnchorMatchesItsDeclaredFingerprint is the guard on the one piece
// of material this verifier asks anyone to take on faith.
//
// If the shipped certificate is ever replaced, this fails, and the fingerprint
// has to be changed deliberately and reviewed against the Official Journal.
func TestShippedAnchorMatchesItsDeclaredFingerprint(t *testing.T) {
	t.Parallel()

	certs, err := bootstrap.LOTLSigners()
	require.NoError(t, err)
	require.Len(t, certs, len(bootstrap.LOTLSignerFingerprints))

	for _, c := range certs {
		sum := sha256.Sum256(c.Raw)
		assert.Contains(t, bootstrap.LOTLSignerFingerprints, hex.EncodeToString(sum[:]))
	}
}

// TestShippedAnchorIsTheCommission records what the anchor is, so a replacement
// by an unrelated certificate is visible in the diff of this test.
func TestShippedAnchorIsTheCommission(t *testing.T) {
	t.Parallel()

	certs, err := bootstrap.LOTLSigners()
	require.NoError(t, err)
	require.NotEmpty(t, certs)

	assert.Equal(t, "EUROPEAN COMMISSION", certs[0].Subject.CommonName)
	assert.Contains(t, certs[0].Subject.Organization, "EUROPEAN COMMISSION")
}

// TestShippedAnchorValidity reports when the anchor expires.
//
// It does not fail on expiry: a list issued while the certificate was valid must
// stay verifiable afterwards. It fails only if the material is absurd, and it
// exists so that the rotation is noticed rather than discovered.
func TestShippedAnchorValidity(t *testing.T) {
	t.Parallel()

	certs, err := bootstrap.LOTLSigners()
	require.NoError(t, err)

	for _, c := range certs {
		assert.True(t, c.NotBefore.Before(c.NotAfter))

		if time.Now().After(c.NotAfter) {
			t.Logf("the bootstrap anchor %q expired on %s; a newer one published in the "+
				"Official Journal should be added to the set",
				c.Subject.CommonName, c.NotAfter.Format(time.RFC3339))
		}
	}
}

func TestLOTLLocationIsTheOfficialPublication(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "https://ec.europa.eu/tools/lotl/eu-lotl.xml", bootstrap.LOTLLocation)
}

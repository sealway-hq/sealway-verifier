// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package verifier_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"

	"github.com/sealway-hq/sealway-verifier/internal/prooftest"
	"github.com/sealway-hq/sealway-verifier/packages/verifier"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/report"
)

// TestVerifyTimestampReportsOnlyWhatItWasAsked states the shape of a token-only
// run.
//
// A bare token is a statement about a digest and a moment. Emitting skipped
// checks for sources, Merkle trees and anchors would report the absence of
// things that were never part of the question.
func TestVerifyTimestampReportsOnlyWhatItWasAsked(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})
	provider, signer := trustFor(t, p)

	v := verifier.New(verifier.WithTrustProvider(provider), verifier.WithTrustListSigners(signer))

	r, err := v.VerifyTimestamp(t.Context(), verifier.TimestampInput{Token: p.Token})
	require.NoError(t, err)

	require.Len(t, r.Sections, 1)
	assert.Equal(t, report.SectionTimestamp, r.Sections[0].ID)

	for _, c := range r.Sections[0].Checks {
		assert.NotEqual(t, report.StatusInvalid, c.Status, "check %s", c.ID)
	}
}

// TestVerifyTimestampEstablishesQualifiedStatusOnItsOwn is the case the entry
// point exists for: a token, a Trusted List, and a verdict about the authority
// that issued it.
func TestVerifyTimestampEstablishesQualifiedStatusOnItsOwn(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})
	provider, signer := trustFor(t, p)

	v := verifier.New(verifier.WithTrustProvider(provider), verifier.WithTrustListSigners(signer))

	r, err := v.VerifyTimestamp(t.Context(), verifier.TimestampInput{Token: p.Token})
	require.NoError(t, err)

	assert.Equal(t, report.StatusValid, statusOf(t, r, "timestamp.structure"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "timestamp.signature"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "timestamp.signer_usage"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "timestamp.trust_chain"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "timestamp.qualified"))
}

// TestATokenVerifiesIdenticallyAloneAndInsideItsProof is the property that
// keeps the two entry points from drifting.
//
// The token path exists to answer a narrower question, not a different one. Any
// timestamp check that concludes one thing inside a bundle and another on its
// own would mean two implementations of the same rule.
func TestATokenVerifiesIdenticallyAloneAndInsideItsProof(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})
	provider, signer := trustFor(t, p)

	v := verifier.New(verifier.WithTrustProvider(provider), verifier.WithTrustListSigners(signer))

	archive, err := p.Bundle(prooftest.BundleOptions{})
	require.NoError(t, err)

	full, err := v.VerifyBundle(t.Context(), bytes.NewReader(archive), int64(len(archive)))
	require.NoError(t, err)

	alone, err := v.VerifyTimestamp(t.Context(), verifier.TimestampInput{
		Token:      p.Token,
		Imprint:    p.MerkleRoot,
		Chain:      p.Chain,
		Revocation: p.Revocation,
	})
	require.NoError(t, err)

	// Everything the bundle established about the timestamp, the token alone
	// establishes too, once it is handed the same material.
	for _, c := range timestampSection(t, full).Checks {
		if c.ID == "timestamp.metadata" {
			continue // compares against a manifest, which a bare token has none of
		}

		assert.Equal(t, c.Status, statusOf(t, alone, c.ID), "check %s", c.ID)
	}
}

// TestTimestampImprintIsComparedOnlyWhenTheCallerSaysWithWhat keeps a token
// tool from claiming more than it was told.
func TestTimestampImprintIsComparedOnlyWhenTheCallerSaysWithWhat(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})
	v := verifier.New(verifier.WithOffline())

	t.Run("no expected digest leaves it unasked", func(t *testing.T) {
		t.Parallel()

		r, err := v.VerifyTimestamp(t.Context(), verifier.TimestampInput{Token: p.Token})
		require.NoError(t, err)

		c, ok := r.Check("timestamp.imprint")
		require.True(t, ok)
		assert.Equal(t, report.StatusSkipped, c.Status)
		assert.Contains(t, c.Message, "No expected digest")
	})

	t.Run("the right digest verifies", func(t *testing.T) {
		t.Parallel()

		r, err := v.VerifyTimestamp(t.Context(), verifier.TimestampInput{
			Token: p.Token, Imprint: p.MerkleRoot,
		})
		require.NoError(t, err)
		assert.Equal(t, report.StatusValid, statusOf(t, r, "timestamp.imprint"))
	})

	t.Run("the wrong digest fails", func(t *testing.T) {
		t.Parallel()

		wrong := make([]byte, len(p.MerkleRoot))
		copy(wrong, p.MerkleRoot)
		wrong[0] ^= 0xff

		r, err := v.VerifyTimestamp(t.Context(), verifier.TimestampInput{
			Token: p.Token, Imprint: wrong,
		})
		require.NoError(t, err)
		assert.Equal(t, report.StatusInvalid, statusOf(t, r, "timestamp.imprint"))
	})
}

// TestTimestampMetadataIsOutOfScopeWithoutAManifest records that comparing the
// token with a manifest is impossible rather than failed, and that it does not
// drag the result down.
func TestTimestampMetadataIsOutOfScopeWithoutAManifest(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	r, err := verifier.New(verifier.WithOffline()).
		VerifyTimestamp(t.Context(), verifier.TimestampInput{Token: p.Token})
	require.NoError(t, err)

	c, ok := r.Check("timestamp.metadata")
	require.True(t, ok)
	assert.Equal(t, report.StatusSkipped, c.Status)
	assert.False(t, c.AffectsCompleteness)
}

// TestVerifyTimestampReadsSuppliedRevocationEvidence covers the material a
// caller holds outside a certificate.
func TestVerifyTimestampReadsSuppliedRevocationEvidence(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{
		Files:      prooftest.DefaultFiles(1),
		Revocation: &prooftest.RevocationOptions{Status: ocsp.Good},
	})

	v := verifier.New(verifier.WithOffline())

	without, err := v.VerifyTimestamp(t.Context(), verifier.TimestampInput{Token: p.Token})
	require.NoError(t, err)
	assert.Equal(t, report.StatusSkipped, statusOf(t, without, "timestamp.revocation"))

	with, err := v.VerifyTimestamp(t.Context(), verifier.TimestampInput{
		Token:      p.Token,
		Chain:      p.TSA.RootDER,
		Revocation: p.Revocation,
	})
	require.NoError(t, err)
	assert.Equal(t, report.StatusValid, statusOf(t, with, "timestamp.revocation"))
}

// TestVerifyTimestampRefusesNothing keeps an empty input an operational error
// rather than a verdict.
func TestVerifyTimestampRefusesNothing(t *testing.T) {
	t.Parallel()

	_, err := verifier.New().VerifyTimestamp(t.Context(), verifier.TimestampInput{})
	require.ErrorIs(t, err, verifier.ErrInvalidInput)
}

// TestVerifyTimestampReportsAnUnreadableTokenRatherThanFailing keeps the report
// shape stable: rubbish in still produces a report saying what is wrong.
func TestVerifyTimestampReportsAnUnreadableTokenRatherThanFailing(t *testing.T) {
	t.Parallel()

	r, err := verifier.New().VerifyTimestamp(t.Context(),
		verifier.TimestampInput{Token: []byte("not a token")})
	require.NoError(t, err)

	assert.Equal(t, report.StatusInvalid, statusOf(t, r, "timestamp.structure"))
	assert.Equal(t, report.ResultInvalid, r.Result)
}

// TestInspectTimestampNamesWhoIssuedIt covers the identity a verdict does not
// carry and a reader needs.
func TestInspectTimestampNamesWhoIssuedIt(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	d, err := verifier.InspectTimestamp(p.Token)
	require.NoError(t, err)

	require.NotNil(t, d.Signer)
	assert.Equal(t, "Sealway Verifier Test TSU", d.Signer.CommonName)
	assert.Equal(t, "Sealway Verifier Test TSA Root", d.Signer.IssuerCommonName)
	assert.NotEmpty(t, d.Signer.Subject)
	assert.NotEmpty(t, d.Signer.SerialNumber)
	assert.NotEmpty(t, d.Signer.SignatureAlgorithm)
	assert.Len(t, d.Signer.SHA256Fingerprint, 64)
	assert.Contains(t, d.Signer.ExtKeyUsage, "timestamping")
	assert.NotEmpty(t, d.Signer.OCSPServers)

	assert.NotEmpty(t, d.GenTime)
	assert.NotEmpty(t, d.MessageImprint)
	assert.Equal(t, "SHA-512", d.HashAlgorithm)
	// The generated authority emits no ETSI statement, and the field says so.
	// Whether a token carries that claim is worth reporting either way: it is a
	// claim by its issuer and never evidence of anything.
	assert.False(t, d.QualifiedStatement)

	_, err = verifier.InspectTimestamp(nil)
	require.ErrorIs(t, err, verifier.ErrInvalidInput)
}

// TestRequiredTerritoryNamesTheListAProofNeeds is what lets a caller fetch one
// national list instead of every list the European Union publishes.
func TestRequiredTerritoryNamesTheListAProofNeeds(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{Files: prooftest.DefaultFiles(1)})

	territory, err := verifier.RequiredTerritory(p.Token)
	require.NoError(t, err)
	assert.Equal(t, "ES", territory)
}

// TestRequiredTerritoryIsEmptyWhenTheCertificateNamesNoCountry keeps it honest:
// an unanswerable question returns nothing rather than a guess.
func TestRequiredTerritoryIsEmptyWhenTheCertificateNamesNoCountry(t *testing.T) {
	t.Parallel()

	tsa, err := prooftest.NewTSA(prooftest.TSAOptions{OmitCountry: true})
	require.NoError(t, err)

	p, err := prooftest.New(prooftest.Options{Files: prooftest.DefaultFiles(1), TSA: tsa})
	require.NoError(t, err)

	territory, err := verifier.RequiredTerritory(p.Token)
	require.NoError(t, err)
	assert.Empty(t, territory)
}

// timestampSection returns the timestamp section of a report, so a test can
// compare it with what a token-only run produced.
func timestampSection(t *testing.T, r *report.Report) report.Section {
	t.Helper()

	for _, s := range r.Sections {
		if s.ID == report.SectionTimestamp {
			return s
		}
	}

	t.Fatal("the report carries no timestamp section")

	return report.Section{}
}

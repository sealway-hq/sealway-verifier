// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package revocation_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"

	"github.com/sealway-hq/sealway-verifier/packages/verifier/revocation"
)

// signed is the instant a timestamp asserts. Every question is asked about it.
var signed = time.Date(2026, time.August, 14, 8, 30, 27, 0, time.UTC)

// authority is a throwaway certification authority together with the leaf it
// issued, which is the certificate every test asks about.
type authority struct {
	issuerCert *x509.Certificate
	issuerKey  *ecdsa.PrivateKey
	leafCert   *x509.Certificate
}

func newAuthority(t *testing.T) *authority {
	t.Helper()

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuerTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Issuing Authority"},
		NotBefore:             signed.Add(-365 * 24 * time.Hour),
		NotAfter:              signed.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	issuerCert := selfSign(t, issuerTmpl, issuerKey)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "Test Signing Unit"},
		NotBefore:    signed.Add(-24 * time.Hour),
		NotAfter:     signed.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, leafTmpl, issuerCert, &leafKey.PublicKey, issuerKey)
	require.NoError(t, err)

	leafCert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return &authority{issuerCert: issuerCert, issuerKey: issuerKey, leafCert: leafCert}
}

func selfSign(t *testing.T, tmpl *x509.Certificate, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert
}

// respond signs an OCSP response as the issuer itself.
func (a *authority) respond(t *testing.T, tmpl ocsp.Response) []byte {
	t.Helper()

	if tmpl.SerialNumber == nil {
		tmpl.SerialNumber = a.leafCert.SerialNumber
	}

	if tmpl.ThisUpdate.IsZero() {
		tmpl.ThisUpdate = signed.Add(time.Hour)
	}

	tmpl.NextUpdate = tmpl.ThisUpdate.Add(24 * time.Hour)

	der, err := ocsp.CreateResponse(a.issuerCert, a.issuerCert, tmpl, a.issuerKey)
	require.NoError(t, err)

	return der
}

// delegate issues a responder certificate and answers with it, which is how an
// authority that does not sign its own responses is set up.
func (a *authority) delegate(t *testing.T, withOCSPSigning bool, tmpl ocsp.Response) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	responderTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "Test Delegated Responder"},
		NotBefore:    signed.Add(-24 * time.Hour),
		NotAfter:     signed.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	if withOCSPSigning {
		responderTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
	}

	der, err := x509.CreateCertificate(rand.Reader, responderTmpl, a.issuerCert, &key.PublicKey, a.issuerKey)
	require.NoError(t, err)

	responderCert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	if tmpl.SerialNumber == nil {
		tmpl.SerialNumber = a.leafCert.SerialNumber
	}

	if tmpl.ThisUpdate.IsZero() {
		tmpl.ThisUpdate = signed.Add(time.Hour)
	}

	tmpl.NextUpdate = tmpl.ThisUpdate.Add(24 * time.Hour)
	// CreateResponse embeds a responder certificate only when the template
	// carries one; the parameter alone just names the responder.
	tmpl.Certificate = responderCert

	out, err := ocsp.CreateResponse(a.issuerCert, responderCert, tmpl, key)
	require.NoError(t, err)

	return out
}

func (a *authority) check(t *testing.T, responses ...[]byte) (*revocation.Result, error) {
	t.Helper()

	return revocation.Check(responses, a.leafCert, a.issuerCert, signed)
}

// TestGoodEstablishesTheCertificateWasUsable is the case the whole package
// exists for.
func TestGoodEstablishesTheCertificateWasUsable(t *testing.T) {
	t.Parallel()

	a := newAuthority(t)

	got, err := a.check(t, a.respond(t, ocsp.Response{Status: ocsp.Good}))
	require.NoError(t, err)

	assert.Equal(t, revocation.StatusGood, got.Status)
	assert.Equal(t, time.Hour, got.Freshness, "the answer was current an hour after the signature")
	assert.False(t, got.Delegated)
	assert.Equal(t, "Test Issuing Authority", got.Responder)
}

// TestRevokedBeforeTheSignatureFails covers the finding that matters: the
// certificate was already withdrawn when it signed.
func TestRevokedBeforeTheSignatureFails(t *testing.T) {
	t.Parallel()

	a := newAuthority(t)

	got, err := a.check(t, a.respond(t, ocsp.Response{
		Status:           ocsp.Revoked,
		RevokedAt:        signed.Add(-48 * time.Hour),
		RevocationReason: ocsp.Superseded,
	}))
	require.NoError(t, err)

	assert.Equal(t, revocation.StatusRevoked, got.Status)
	assert.Equal(t, "superseded", got.ReasonName)
}

// TestRevokedAtTheSameInstantFails keeps the boundary closed: a certificate
// revoked at the very instant it signed was not usable.
func TestRevokedAtTheSameInstantFails(t *testing.T) {
	t.Parallel()

	a := newAuthority(t)

	got, err := a.check(t, a.respond(t, ocsp.Response{
		Status:           ocsp.Revoked,
		RevokedAt:        signed,
		RevocationReason: ocsp.CessationOfOperation,
	}))
	require.NoError(t, err)

	assert.Equal(t, revocation.StatusRevoked, got.Status)
}

// TestRevokedAfterTheSignatureDoesNotReachBack states the temporal rule the
// package is built around.
//
// A key retired, superseded or withdrawn after a timestamp was made was still
// recognised when it signed. Treating that as failure would invalidate every
// proof an authority ever made as soon as it rotated a certificate.
func TestRevokedAfterTheSignatureDoesNotReachBack(t *testing.T) {
	t.Parallel()

	for name, reason := range map[string]int{
		"superseded":             ocsp.Superseded,
		"cessation of operation": ocsp.CessationOfOperation,
		"privilege withdrawn":    ocsp.PrivilegeWithdrawn,
		"unspecified":            ocsp.Unspecified,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			a := newAuthority(t)

			got, err := a.check(t, a.respond(t, ocsp.Response{
				Status:           ocsp.Revoked,
				RevokedAt:        signed.Add(72 * time.Hour),
				RevocationReason: reason,
			}))
			require.NoError(t, err)

			assert.Equal(t, revocation.StatusRevokedLater, got.Status)
			assert.Equal(t, signed.Add(72*time.Hour), got.RevokedAt)
		})
	}
}

// TestCompromiseAfterTheSignatureIsUndecided is the exception, and the reason
// the rule above cannot simply be "later revocations do not count".
//
// A compromise has no start date in the evidence. The key may have been in
// someone else's hands well before anyone noticed, so a timestamp made before
// the revocation is neither established nor refuted.
func TestCompromiseAfterTheSignatureIsUndecided(t *testing.T) {
	t.Parallel()

	for name, reason := range map[string]int{
		"key compromise":                     ocsp.KeyCompromise,
		"certification authority compromise": ocsp.CACompromise,
		"attribute authority compromise":     ocsp.AACompromise,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			a := newAuthority(t)

			got, err := a.check(t, a.respond(t, ocsp.Response{
				Status:           ocsp.Revoked,
				RevokedAt:        signed.Add(72 * time.Hour),
				RevocationReason: reason,
			}))
			require.NoError(t, err)

			assert.Equal(t, revocation.StatusUndetermined, got.Status,
				"a compromise may predate the signature; nothing here says otherwise")
			assert.NotEmpty(t, got.ReasonName)
		})
	}
}

// TestStaleEvidenceIsRefused is what stops substitution.
//
// Evidence current before the instant asked about cannot answer it, and
// accepting it would let an older and more convenient answer stand in for the
// one that covers the question.
func TestStaleEvidenceIsRefused(t *testing.T) {
	t.Parallel()

	a := newAuthority(t)

	_, err := a.check(t, a.respond(t, ocsp.Response{
		Status:     ocsp.Good,
		ThisUpdate: signed.Add(-time.Second),
	}))
	require.ErrorIs(t, err, revocation.ErrStale)
}

// TestEvidenceCurrentAtTheSameInstantIsAccepted keeps the boundary open on the
// other side: an answer current exactly at the asserted time does cover it.
func TestEvidenceCurrentAtTheSameInstantIsAccepted(t *testing.T) {
	t.Parallel()

	a := newAuthority(t)

	got, err := a.check(t, a.respond(t, ocsp.Response{Status: ocsp.Good, ThisUpdate: signed}))
	require.NoError(t, err)

	assert.Equal(t, revocation.StatusGood, got.Status)
	assert.Zero(t, got.Freshness)
}

// TestADelegatedResponderMustCarryTheOCSPSigningUsage closes a gap the parsing
// library leaves open.
//
// Verifying that a response is signed by a certificate the issuer signed is not
// enough: that set contains every certificate the authority ever issued. RFC
// 6960 section 4.2.2.2 narrows it to the ones the authority actually delegated
// to, by requiring the OCSP signing extended key usage.
func TestADelegatedResponderMustCarryTheOCSPSigningUsage(t *testing.T) {
	t.Parallel()

	a := newAuthority(t)

	got, err := a.check(t, a.delegate(t, true, ocsp.Response{Status: ocsp.Good}))
	require.NoError(t, err)
	assert.Equal(t, revocation.StatusGood, got.Status)
	assert.True(t, got.Delegated)
	assert.Equal(t, "Test Delegated Responder", got.Responder)

	_, err = a.check(t, a.delegate(t, false, ocsp.Response{Status: ocsp.Good}))
	require.ErrorIs(t, err, revocation.ErrUntrustedResponder,
		"a certificate the authority signed is not thereby authorised to answer for it")
}

// TestEvidenceFromAnotherAuthorityIsRefused keeps supplied evidence material
// rather than authority: it is checked against the issuer before it is read.
func TestEvidenceFromAnotherAuthorityIsRefused(t *testing.T) {
	t.Parallel()

	a, stranger := newAuthority(t), newAuthority(t)

	// The stranger answers about a certificate with the same serial, signed by
	// a key the real issuer never had.
	forged := stranger.respond(t, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: a.leafCert.SerialNumber,
	})

	_, err := a.check(t, forged)
	require.ErrorIs(t, err, revocation.ErrMalformed,
		"the evidence was found and rejected, not silently ignored")
}

// TestEvidenceForAnotherCertificateIsIgnored lets a proof carry evidence for a
// whole path without the responses for other certificates counting as failures.
func TestEvidenceForAnotherCertificateIsIgnored(t *testing.T) {
	t.Parallel()

	a := newAuthority(t)

	other := a.respond(t, ocsp.Response{Status: ocsp.Good, SerialNumber: big.NewInt(999)})
	ours := a.respond(t, ocsp.Response{Status: ocsp.Good})

	got, err := a.check(t, other, ours)
	require.NoError(t, err)
	assert.Equal(t, revocation.StatusGood, got.Status)

	// On its own it establishes nothing about our certificate.
	_, err = a.check(t, other)
	require.Error(t, err)
}

// TestUnknownIsUndecided records that a responder which does not recognise a
// certificate has told us nothing, which is not the same as telling us it is
// fine.
func TestUnknownIsUndecided(t *testing.T) {
	t.Parallel()

	a := newAuthority(t)

	got, err := a.check(t, a.respond(t, ocsp.Response{Status: ocsp.Unknown}))
	require.NoError(t, err)

	assert.Equal(t, revocation.StatusUndetermined, got.Status)
}

// TestNoEvidenceIsAnAbsence keeps an empty hand distinguishable from a finding.
func TestNoEvidenceIsAnAbsence(t *testing.T) {
	t.Parallel()

	a := newAuthority(t)

	_, err := a.check(t)
	require.ErrorIs(t, err, revocation.ErrNoEvidence)
}

// TestUnreadableEvidenceSaysSo makes a proof carrying only rubbish report why,
// rather than looking as though it carried nothing.
func TestUnreadableEvidenceSaysSo(t *testing.T) {
	t.Parallel()

	a := newAuthority(t)

	_, err := a.check(t, []byte("this is not an OCSP response"))
	require.Error(t, err)
	assert.ErrorIs(t, err, revocation.ErrMalformed)
}

// TestMissingInputsAreRefused covers the guard, because a nil issuer would make
// the parsing library skip signature verification entirely.
func TestMissingInputsAreRefused(t *testing.T) {
	t.Parallel()

	a := newAuthority(t)
	der := a.respond(t, ocsp.Response{Status: ocsp.Good})

	_, err := revocation.Check([][]byte{der}, nil, a.issuerCert, signed)
	require.ErrorIs(t, err, revocation.ErrMalformed)

	_, err = revocation.Check([][]byte{der}, a.leafCert, nil, signed)
	require.ErrorIs(t, err, revocation.ErrMalformed)
}

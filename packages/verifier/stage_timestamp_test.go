// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package verifier_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealway-hq/sealway-verifier/internal/prooftest"
	"github.com/sealway-hq/sealway-verifier/packages/verifier"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/report"
)

// TestTimestampResponseStatusIsChecked covers a timestamping authority that
// refused to issue a token: the artifact parses, but it grants nothing.
func TestTimestampResponseStatusIsChecked(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{
		Files: prooftest.DefaultFiles(1),
		TokenOptions: &prooftest.TokenOptions{
			WrapInResponse: true,
			ResponseStatus: 2, // rejection
		},
	})

	r, err := offline().VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), nil)
	require.NoError(t, err)

	assert.Equal(t, report.ResultInvalid, r.Result)
	assert.Equal(t, report.StatusInvalid, statusOf(t, r, "timestamp.structure"))
}

func TestTimestampResponseEnvelopeIsAccepted(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{
		Files:        prooftest.DefaultFiles(1),
		TokenOptions: &prooftest.TokenOptions{WrapInResponse: true},
	})

	r, err := offline().VerifyCertificate(t.Context(),
		bytes.NewReader(p.Certificate), sourcesFor(p.Files))
	require.NoError(t, err)

	assert.Equal(t, report.StatusValid, statusOf(t, r, "timestamp.structure"))
	assert.Equal(t, report.StatusValid, statusOf(t, r, "timestamp.imprint"))

	c, _ := r.Check("timestamp.structure")
	assert.Equal(t, "0 (granted)", c.Details["response_status"])
}

func TestTimestampVersionIsChecked(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{
		Files:        prooftest.DefaultFiles(1),
		TokenOptions: &prooftest.TokenOptions{Version: 3},
	})

	r, err := offline().VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), nil)
	require.NoError(t, err)

	assert.Equal(t, report.StatusInvalid, statusOf(t, r, "timestamp.structure"))

	c, _ := r.Check("timestamp.structure")
	assert.Contains(t, c.Message, "version 3")
}

// TestTimestampImprintAlgorithmIsChecked covers a token that is genuine but
// covers a digest of the wrong algorithm, so it cannot possibly cover a Sealway
// proof root.
func TestTimestampImprintAlgorithmIsChecked(t *testing.T) {
	t.Parallel()

	sha256OID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

	p := newProof(t, prooftest.Options{
		Files: prooftest.DefaultFiles(1),
		TokenOptions: &prooftest.TokenOptions{
			Imprint: bytes.Repeat([]byte{0x07}, 32),
			HashOID: sha256OID,
		},
	})

	r, err := offline().VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), nil)
	require.NoError(t, err)

	assert.Equal(t, report.StatusInvalid, statusOf(t, r, "timestamp.imprint"))

	c, _ := r.Check("timestamp.imprint")
	assert.Contains(t, c.Message, "SHA-256")
}

// TestTimestampWithoutCertificatesSkipsTheSignature records that a token that
// embeds no signer certificate cannot have its signature verified, and that this
// is reported as skipped rather than assumed valid.
func TestTimestampWithoutCertificatesSkipsTheSignature(t *testing.T) {
	t.Parallel()

	p := newProof(t, prooftest.Options{
		Files:        prooftest.DefaultFiles(1),
		TokenOptions: &prooftest.TokenOptions{OmitCertificates: true},
	})

	r, err := offline().VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), nil)
	require.NoError(t, err)

	assert.Equal(t, report.StatusSkipped, statusOf(t, r, "timestamp.signature"))
	assert.Equal(t, report.StatusSkipped, statusOf(t, r, "timestamp.signer_usage"))

	// The imprint is still compared, because it does not depend on the signature.
	assert.Equal(t, report.StatusValid, statusOf(t, r, "timestamp.imprint"))
	assert.Equal(t, report.ResultPartialValid, r.Result)
}

// TestSignerUsageIsChecked covers the RFC 3161 requirement that a timestamping
// certificate carries the timeStamping extended key usage.
func TestSignerUsageIsChecked(t *testing.T) {
	t.Parallel()

	t.Run("missing timestamping usage", func(t *testing.T) {
		t.Parallel()

		tsa := customTSA(t, func(tmpl *x509.Certificate) {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		})

		p := signedWith(t, tsa)

		r, err := offline().VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), nil)
		require.NoError(t, err)

		assert.Equal(t, report.StatusInvalid, statusOf(t, r, "timestamp.signer_usage"))

		c, _ := r.Check("timestamp.signer_usage")
		assert.Contains(t, c.Message, "timeStamping")
	})

	t.Run("signer expired before the asserted time", func(t *testing.T) {
		t.Parallel()

		tsa := customTSA(t, func(tmpl *x509.Certificate) {
			tmpl.NotBefore = prooftest.DefaultGenTime.Add(-400 * 24 * time.Hour)
			tmpl.NotAfter = prooftest.DefaultGenTime.Add(-300 * 24 * time.Hour)
		})

		p := signedWith(t, tsa)

		r, err := offline().VerifyCertificate(t.Context(), bytes.NewReader(p.Certificate), nil)
		require.NoError(t, err)

		assert.Equal(t, report.StatusInvalid, statusOf(t, r, "timestamp.signer_usage"))

		c, _ := r.Check("timestamp.signer_usage")
		assert.Contains(t, c.Message, "validity period")
	})
}

// customTSA builds a throwaway authority whose timestamping certificate is
// adjusted by the given function.
func customTSA(t *testing.T, adjust func(*x509.Certificate)) *prooftest.TSA {
	t.Helper()

	tsa, err := prooftest.NewTSA()
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "Sealway Verifier Adjusted TSU"},
		NotBefore:             prooftest.DefaultGenTime.Add(-24 * time.Hour),
		NotAfter:              prooftest.DefaultGenTime.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
	}

	adjust(tmpl)

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tsa.RootCert, &key.PublicKey, tsa.RootKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	tsa.SignerCert, tsa.SignerKey, tsa.SignerDER = cert, key, der

	return tsa
}

// signedWith builds a proof whose token is signed by the given authority.
func signedWith(t *testing.T, tsa *prooftest.TSA) *prooftest.Proof {
	t.Helper()

	files := prooftest.DefaultFiles(1)

	sum := sha512.Sum512(files[0].Content)

	root, err := verifier.ComputeMerkleRoot([][]byte{sum[:]})
	require.NoError(t, err)

	token, err := tsa.Token(prooftest.TokenOptions{
		Imprint:    root,
		SignerCert: tsa.SignerCert,
		SignerKey:  tsa.SignerKey,
	})
	require.NoError(t, err)

	return newProof(t, prooftest.Options{Files: files, Token: token})
}

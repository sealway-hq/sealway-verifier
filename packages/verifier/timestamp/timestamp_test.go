// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package timestamp_test

import (
	"bytes"
	"crypto"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealway-hq/sealway-verifier/internal/prooftest"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/timestamp"
)

func imprint() []byte {
	sum := sha512.Sum512([]byte("the proof merkle root"))

	return sum[:]
}

func newTSA(t *testing.T) *prooftest.TSA {
	t.Helper()

	tsa, err := prooftest.NewTSA()
	require.NoError(t, err)

	return tsa
}

func TestParseBareToken(t *testing.T) {
	t.Parallel()

	tsa := newTSA(t)

	der, err := tsa.Token(prooftest.TokenOptions{Imprint: imprint()})
	require.NoError(t, err)

	token, err := timestamp.Parse(der)
	require.NoError(t, err)

	assert.Nil(t, token.ResponseStatus)
	assert.Equal(t, 1, token.Version)
	assert.Equal(t, prooftest.DefaultPolicyOID.String(), token.Policy)
	assert.Equal(t, crypto.SHA512, token.HashAlgorithm)
	assert.Equal(t, "SHA-512", token.HashAlgorithmName)
	assert.Equal(t, imprint(), token.MessageImprint)
	assert.Equal(t, "4242", token.SerialNumber)
	assert.True(t, token.GenTime.Equal(prooftest.DefaultGenTime))
	assert.Len(t, token.Certificates, 1)
	assert.NotNil(t, token.Signer)
	assert.Contains(t, token.SignerSubject(), "Sealway Verifier Test TSU")
	assert.Contains(t, token.SignerIssuer(), "Sealway Verifier Test TSA Root")
	assert.True(t, token.HasTimestampingUsage())
	assert.NotEmpty(t, token.Raw)
}

func TestParseFullResponse(t *testing.T) {
	t.Parallel()

	tsa := newTSA(t)

	der, err := tsa.Token(prooftest.TokenOptions{Imprint: imprint(), WrapInResponse: true})
	require.NoError(t, err)

	token, err := timestamp.Parse(der)
	require.NoError(t, err)

	require.NotNil(t, token.ResponseStatus)
	assert.Equal(t, 0, token.ResponseStatus.Status)
	assert.Equal(t, "granted", token.ResponseStatus.Name)
	assert.True(t, token.ResponseStatus.Granted())
	assert.Equal(t, imprint(), token.MessageImprint)
}

func TestParseRejectedResponse(t *testing.T) {
	t.Parallel()

	tsa := newTSA(t)

	der, err := tsa.Token(prooftest.TokenOptions{
		Imprint:        imprint(),
		WrapInResponse: true,
		ResponseStatus: 2,
	})
	require.NoError(t, err)

	_, err = timestamp.Parse(der)
	assert.ErrorIs(t, err, timestamp.ErrNoToken)
}

func TestVerifySignature(t *testing.T) {
	t.Parallel()

	tsa := newTSA(t)

	der, err := tsa.Token(prooftest.TokenOptions{Imprint: imprint()})
	require.NoError(t, err)

	token, err := timestamp.Parse(der)
	require.NoError(t, err)
	assert.NoError(t, token.VerifySignature())
}

func TestVerifySignatureRejectsTamperedToken(t *testing.T) {
	t.Parallel()

	tsa := newTSA(t)

	der, err := tsa.Token(prooftest.TokenOptions{Imprint: imprint(), CorruptSignature: true})
	require.NoError(t, err)

	token, err := timestamp.Parse(der)
	require.NoError(t, err, "a corrupted signature must still parse, so it can be reported precisely")
	assert.Error(t, token.VerifySignature())
}

// TestVerifySignatureRejectsForeignSigner checks that a token signed by a
// different key than the certificate it carries does not verify.
func TestVerifySignatureRejectsForeignSigner(t *testing.T) {
	t.Parallel()

	first, second := newTSA(t), newTSA(t)

	der, err := first.Token(prooftest.TokenOptions{
		Imprint:    imprint(),
		SignerCert: first.SignerCert,
		SignerKey:  second.SignerKey,
	})
	require.NoError(t, err)

	token, err := timestamp.Parse(der)
	require.NoError(t, err)
	assert.Error(t, token.VerifySignature())
}

func TestVerifyImprint(t *testing.T) {
	t.Parallel()

	tsa := newTSA(t)

	der, err := tsa.Token(prooftest.TokenOptions{Imprint: imprint()})
	require.NoError(t, err)

	token, err := timestamp.Parse(der)
	require.NoError(t, err)

	assert.True(t, token.VerifyImprint(imprint()))
	assert.False(t, token.VerifyImprint(bytes.Repeat([]byte{0x01}, 64)))
	assert.False(t, token.VerifyImprint(nil))
	assert.False(t, token.VerifyImprint(imprint()[:63]))
}

func TestUnsupportedHashAlgorithmIsReported(t *testing.T) {
	t.Parallel()

	tsa := newTSA(t)

	sha256OID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

	der, err := tsa.Token(prooftest.TokenOptions{
		Imprint: bytes.Repeat([]byte{0x07}, 32),
		HashOID: sha256OID,
	})
	require.NoError(t, err)

	token, err := timestamp.Parse(der)
	require.NoError(t, err)
	assert.Equal(t, crypto.SHA256, token.HashAlgorithm)
	assert.Equal(t, "SHA-256", token.HashAlgorithmName)

	unknown := asn1.ObjectIdentifier{1, 2, 3, 4, 5}

	der, err = tsa.Token(prooftest.TokenOptions{Imprint: imprint(), HashOID: unknown})
	require.NoError(t, err)

	token, err = timestamp.Parse(der)
	require.NoError(t, err)
	assert.Equal(t, crypto.Hash(0), token.HashAlgorithm)
	assert.Equal(t, "1.2.3.4.5", token.HashAlgorithmName)
}

func TestParseRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	tsa := newTSA(t)

	valid, err := tsa.Token(prooftest.TokenOptions{Imprint: imprint()})
	require.NoError(t, err)

	cases := map[string][]byte{
		"empty":           {},
		"garbage":         []byte("this is not DER at all"),
		"truncated":       valid[:len(valid)/2],
		"trailing bytes":  append(bytes.Clone(valid), 0x00, 0x01, 0x02),
		"single zero":     {0x00},
		"empty sequence":  {0x30, 0x00},
		"header only":     {0x30, 0x82, 0x0f, 0xbe},
		"leading garbage": append([]byte{0x01, 0x02}, valid...),
	}

	for name, der := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := timestamp.Parse(der)
			assert.Error(t, err)
		})
	}
}

func TestParseRejectsOversizedArtifact(t *testing.T) {
	t.Parallel()

	_, err := timestamp.Parse(make([]byte, timestamp.DefaultMaxSize+1))
	assert.ErrorIs(t, err, timestamp.ErrTooLarge)
}

// TestParseRejectsWrongContentType checks that a CMS SignedData that is not a
// timestamp token is refused, rather than having its payload reinterpreted.
func TestParseRejectsWrongContentType(t *testing.T) {
	t.Parallel()

	tsa := newTSA(t)

	oidData := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}

	der, err := tsa.Token(prooftest.TokenOptions{Imprint: imprint()})
	require.NoError(t, err)

	// Rebuild the token declaring the generic data content type instead.
	replaced := bytes.Replace(der, mustDER(t, oidCTTSTInfo()), mustDER(t, oidData), 1)
	require.NotEqual(t, string(der), string(replaced))

	_, err = timestamp.Parse(replaced)
	assert.ErrorIs(t, err, timestamp.ErrMalformed)
}

func oidCTTSTInfo() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
}

func mustDER(t *testing.T, oid asn1.ObjectIdentifier) []byte {
	t.Helper()

	der, err := asn1.Marshal(oid)
	require.NoError(t, err)

	return der
}

func TestVerifyChain(t *testing.T) {
	t.Parallel()

	tsa := newTSA(t)

	der, err := tsa.Token(prooftest.TokenOptions{Imprint: imprint()})
	require.NoError(t, err)

	token, err := timestamp.Parse(der)
	require.NoError(t, err)

	assert.NoError(t, token.VerifyChain(tsa.RootPool()))

	t.Run("no anchors supplied", func(t *testing.T) {
		t.Parallel()

		err := token.VerifyChain(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no trust anchors")
	})

	t.Run("unrelated anchors", func(t *testing.T) {
		t.Parallel()

		other := newTSA(t)
		assert.Error(t, token.VerifyChain(other.RootPool()))
	})

	t.Run("empty pool", func(t *testing.T) {
		t.Parallel()

		assert.Error(t, token.VerifyChain(x509.NewCertPool()))
	})
}

func TestSignerValidityWindow(t *testing.T) {
	t.Parallel()

	tsa := newTSA(t)

	der, err := tsa.Token(prooftest.TokenOptions{Imprint: imprint()})
	require.NoError(t, err)

	token, err := timestamp.Parse(der)
	require.NoError(t, err)

	assert.True(t, token.SignerValidAt(prooftest.DefaultGenTime))
	assert.False(t, token.SignerValidAt(prooftest.DefaultGenTime.Add(-100*24*time.Hour)))
	assert.False(t, token.SignerValidAt(prooftest.DefaultGenTime.Add(1000*24*time.Hour)))
}

func TestNonDefaultMetadataIsExposed(t *testing.T) {
	t.Parallel()

	tsa := newTSA(t)

	policy := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12345, 9}
	when := time.Date(2027, time.January, 2, 3, 4, 5, 0, time.UTC)

	der, err := tsa.Token(prooftest.TokenOptions{
		Imprint: imprint(),
		Policy:  policy,
		Serial:  big.NewInt(987654321),
		GenTime: when,
	})
	require.NoError(t, err)

	token, err := timestamp.Parse(der)
	require.NoError(t, err)

	assert.Equal(t, policy.String(), token.Policy)
	assert.Equal(t, "987654321", token.SerialNumber)
	assert.True(t, token.GenTime.Equal(when))
}

func TestNilTokenMethodsAreSafe(t *testing.T) {
	t.Parallel()

	var token *timestamp.Token

	assert.ErrorIs(t, token.VerifySignature(), timestamp.ErrMalformed)
	assert.ErrorIs(t, token.VerifyChain(nil), timestamp.ErrMalformed)
	assert.False(t, token.VerifyImprint(imprint()))
	assert.Empty(t, token.SignerSubject())
	assert.Empty(t, token.SignerIssuer())
	assert.False(t, token.HasTimestampingUsage())
	assert.False(t, token.SignerValidAt(time.Now()))
}

func TestResponseStatusGranted(t *testing.T) {
	t.Parallel()

	assert.True(t, timestamp.ResponseStatus{Status: 0}.Granted())
	assert.True(t, timestamp.ResponseStatus{Status: 1}.Granted())
	assert.False(t, timestamp.ResponseStatus{Status: 2}.Granted())
}

// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package xmldsig

import (
	"crypto/x509"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func accepted(s *signerKey) []*x509.Certificate { return []*x509.Certificate{s.cert} }

func TestVerifyAcceptsAWellFormedSignature(t *testing.T) {
	t.Parallel()

	s := newSigner(t, 2048)
	data := signDocument(t, s, signOptions{})

	res, err := Verify(data, accepted(s), Limits{})
	require.NoError(t, err)

	assert.True(t, res.Signer.Equal(s.cert))
	assert.Equal(t, AlgRSASHA256, res.SignatureAlgorithm)
	assert.Equal(t, "TrustServiceStatusList", res.SignedDocument.Tag)
	require.Len(t, res.Certificates, 1)
}

// TestVerifyAcceptsMultipleReferences covers the shape the real lists use: one
// reference over the document and one over the XAdES signed properties.
func TestVerifyAcceptsMultipleReferences(t *testing.T) {
	t.Parallel()

	s := newSigner(t, 2048)
	data := signDocument(t, s, signOptions{extraReference: "xades-properties"})

	res, err := Verify(data, accepted(s), Limits{})
	require.NoError(t, err)
	assert.Len(t, res.DigestAlgorithms, 2)
}

// TestVerifyReturnsOnlyTheVerifiedTree pins the contract that a caller
// interprets what was verified, never the original bytes.
func TestVerifyReturnsOnlyTheVerifiedTree(t *testing.T) {
	t.Parallel()

	s := newSigner(t, 2048)
	data := signDocument(t, s, signOptions{})

	res, err := Verify(data, accepted(s), Limits{})
	require.NoError(t, err)
	require.NotNil(t, res.SignedDocument)

	seq := res.SignedDocument.FindElement("//TSLSequenceNumber")
	require.NotNil(t, seq)
	assert.Equal(t, "1", seq.Text())
}

func TestVerifyDetectsTamperedContent(t *testing.T) {
	t.Parallel()

	s := newSigner(t, 2048)
	data := signDocument(t, s, signOptions{})

	// Change the signed payload after the fact.
	tampered := []byte(strings.Replace(string(data),
		"<TSLSequenceNumber>1</TSLSequenceNumber>",
		"<TSLSequenceNumber>2</TSLSequenceNumber>", 1))
	require.NotEqual(t, string(data), string(tampered))

	_, err := Verify(tampered, accepted(s), Limits{})
	assert.ErrorIs(t, err, ErrDigestMismatch)
}

func TestVerifyDetectsTamperedSignatureValue(t *testing.T) {
	t.Parallel()

	s := newSigner(t, 2048)
	data := signDocument(t, s, signOptions{corruptSignature: true})

	_, err := Verify(data, accepted(s), Limits{})
	assert.ErrorIs(t, err, ErrSignatureInvalid)
}

func TestVerifyDetectsTamperedDigestValue(t *testing.T) {
	t.Parallel()

	s := newSigner(t, 2048)
	data := signDocument(t, s, signOptions{corruptDigest: true})

	// Rewriting a digest also breaks the signature over SignedInfo, so either
	// failure is correct; what matters is that it never verifies.
	_, err := Verify(data, accepted(s), Limits{})
	require.Error(t, err)
	assert.True(t,
		strings.Contains(err.Error(), "digest") || strings.Contains(err.Error(), "signature"),
		"unexpected error: %v", err)
}

func TestVerifyRejectsAnUnacceptedSigner(t *testing.T) {
	t.Parallel()

	s, other := newSigner(t, 2048), newSigner(t, 2048)
	data := signDocument(t, s, signOptions{})

	_, err := Verify(data, accepted(other), Limits{})
	assert.ErrorIs(t, err, ErrUntrustedSigner)

	_, err = Verify(data, nil, Limits{})
	assert.ErrorIs(t, err, ErrUntrustedSigner)
}

// TestVerifyRejectsDuplicateIdentifiers covers the classic XML Signature
// Wrapping primitive: two elements answering to the same reference, so a
// validator digests one while a reader consumes the other.
func TestVerifyRejectsDuplicateIdentifiers(t *testing.T) {
	t.Parallel()

	s := newSigner(t, 2048)
	data := signDocument(t, s, signOptions{
		extraReference: "xades-properties",
		duplicateID:    true,
	})

	_, err := Verify(data, accepted(s), Limits{})
	require.ErrorIs(t, err, ErrMalformed)
	assert.Contains(t, err.Error(), "resolves to 2 elements")
}

// TestVerifyRejectsSeveralSignatures keeps the signed content decidable.
func TestVerifyRejectsSeveralSignatures(t *testing.T) {
	t.Parallel()

	s := newSigner(t, 2048)
	data := signDocument(t, s, signOptions{duplicateSignature: true})

	_, err := Verify(data, accepted(s), Limits{})
	assert.ErrorIs(t, err, ErrAmbiguousSignature)
}

// TestVerifyRejectsANestedSignature refuses a signature that is not a direct
// child of the document element, another wrapping shape.
func TestVerifyRejectsANestedSignature(t *testing.T) {
	t.Parallel()

	s := newSigner(t, 2048)
	data := signDocument(t, s, signOptions{signatureParent: "Wrapper"})

	_, err := Verify(data, accepted(s), Limits{})
	require.ErrorIs(t, err, ErrMalformed)
	assert.Contains(t, err.Error(), "direct child")
}

func TestVerifyRejectsAMissingSignature(t *testing.T) {
	t.Parallel()

	_, err := Verify([]byte(`<TrustServiceStatusList/>`), nil, Limits{})
	assert.ErrorIs(t, err, ErrNoSignature)
}

// TestVerifyRejectsUnsupportedTransforms refuses selection transforms such as
// XPath, which would make the signed subset unreviewable.
func TestVerifyRejectsUnsupportedTransforms(t *testing.T) {
	t.Parallel()

	s := newSigner(t, 2048)

	for _, alg := range []string{
		"http://www.w3.org/TR/1999/REC-xpath-19991116",
		"http://www.w3.org/TR/1999/REC-xslt-19991116",
		"http://www.w3.org/2002/06/xmldsig-filter2",
	} {
		data := signDocument(t, s, signOptions{transform: alg})

		_, err := Verify(data, accepted(s), Limits{})
		assert.ErrorIs(t, err, ErrUnsupportedAlgorithm, "transform %s", alg)
	}
}

// TestVerifyRequiresTheEnvelopedTransform refuses a document reference that does
// not remove the signature from what it digests.
func TestVerifyRequiresTheEnvelopedTransform(t *testing.T) {
	t.Parallel()

	s := newSigner(t, 2048)
	data := signDocument(t, s, signOptions{omitEnveloped: true})

	_, err := Verify(data, accepted(s), Limits{})
	require.ErrorIs(t, err, ErrMalformed)
	assert.Contains(t, err.Error(), "enveloped-signature")
}

// TestVerifyRejectsExternalReferences refuses to fetch anything a document
// points at.
func TestVerifyRejectsExternalReferences(t *testing.T) {
	t.Parallel()

	s := newSigner(t, 2048)

	for _, uri := range []string{
		"https://example.test/payload.xml",
		"file:///etc/passwd",
		"payload.xml",
	} {
		data := signDocument(t, s, signOptions{referenceURI: uri})

		_, err := Verify(data, accepted(s), Limits{})
		require.ErrorIs(t, err, ErrMalformed, "uri %s", uri)
		assert.Contains(t, err.Error(), "same-document")
	}
}

// TestVerifyRequiresAReferenceOverTheDocument refuses a signature that covers
// only a fragment, which would say nothing about the list.
func TestVerifyRequiresAReferenceOverTheDocument(t *testing.T) {
	t.Parallel()

	s := newSigner(t, 2048)
	data := signDocument(t, s, signOptions{
		extraReference: "xades-properties",
		referenceURI:   "#xades-properties",
	})

	_, err := Verify(data, accepted(s), Limits{})
	require.ErrorIs(t, err, ErrMalformed)
	assert.Contains(t, err.Error(), "no reference covers the document")
}

func TestVerifyRejectsWeakKeys(t *testing.T) {
	t.Parallel()

	s := newSigner(t, 1024)
	data := signDocument(t, s, signOptions{})

	_, err := Verify(data, accepted(s), Limits{})
	require.ErrorIs(t, err, ErrUnsupportedAlgorithm)
	assert.Contains(t, err.Error(), "below the 2048 bit minimum")
}

func TestVerifyEnforcesLimits(t *testing.T) {
	t.Parallel()

	s := newSigner(t, 2048)
	data := signDocument(t, s, signOptions{})

	t.Run("size", func(t *testing.T) {
		t.Parallel()

		_, err := Verify(data, accepted(s), Limits{MaxBytes: 16})
		assert.ErrorIs(t, err, ErrLimitExceeded)
	})

	t.Run("depth", func(t *testing.T) {
		t.Parallel()

		_, err := Verify(data, accepted(s), Limits{MaxDepth: 1})
		assert.ErrorIs(t, err, ErrLimitExceeded)
	})

	t.Run("references", func(t *testing.T) {
		t.Parallel()

		withTwo := signDocument(t, s, signOptions{extraReference: "xades-properties"})

		_, err := Verify(withTwo, accepted(s), Limits{MaxReferences: 1})
		assert.ErrorIs(t, err, ErrLimitExceeded)
	})
}

// TestVerifyRejectsMalformedInput checks hostile bytes are refused without a
// panic.
func TestVerifyRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"empty":              "",
		"not xml":            "this is not xml at all",
		"truncated":          `<TrustServiceStatusList><Signature`,
		"no document":        `<?xml version="1.0"?>`,
		"entity declaration": `<!DOCTYPE x [<!ENTITY e "boom">]><x>&e;</x>`,
		"unbalanced":         `<a><b></a></b>`,
	}

	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := Verify([]byte(doc), nil, Limits{})
			assert.Error(t, err)
		})
	}
}

// TestVerifyRejectsUnsupportedAlgorithms refuses anything outside the accepted
// set rather than approximating it.
func TestVerifyRejectsUnsupportedAlgorithms(t *testing.T) {
	t.Parallel()

	s := newSigner(t, 2048)
	data := string(signDocument(t, s, signOptions{}))

	t.Run("signature", func(t *testing.T) {
		t.Parallel()

		swapped := strings.Replace(data, AlgRSASHA256,
			"http://www.w3.org/2000/09/xmldsig#rsa-sha1", 1)

		_, err := Verify([]byte(swapped), accepted(s), Limits{})
		assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
	})

	t.Run("digest", func(t *testing.T) {
		t.Parallel()

		swapped := strings.Replace(data, AlgDigestSHA256,
			"http://www.w3.org/2000/09/xmldsig#sha1", 1)

		_, err := Verify([]byte(swapped), accepted(s), Limits{})
		assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
	})

	t.Run("canonicalization", func(t *testing.T) {
		t.Parallel()

		swapped := strings.Replace(data, AlgExcC14N, "http://example.test/c14n", 1)

		_, err := Verify([]byte(swapped), accepted(s), Limits{})
		assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
	})
}

// FuzzVerify encodes the requirement that untrusted XML never panics.
func FuzzVerify(f *testing.F) {
	f.Add([]byte(`<a/>`))
	f.Add([]byte(`<a><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"/></a>`))
	f.Add([]byte(``))

	s := newSigner(f, 2048)
	f.Add(signDocument(f, s, signOptions{}))

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = Verify(data, []*x509.Certificate{s.cert}, Limits{MaxBytes: 1 << 20})
	})
}

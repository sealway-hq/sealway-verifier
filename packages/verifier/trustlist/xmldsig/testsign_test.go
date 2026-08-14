// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package xmldsig

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

// signerKey is a throwaway signing identity for the tests.
type signerKey struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

func newSigner(t testing.TB, bits int) *signerKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Trusted List Test Operator"},
		NotBefore:    time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return &signerKey{cert: cert, key: key}
}

// signOptions tweaks a generated document, so a test can produce exactly the
// malformed shape it wants to see refused.
type signOptions struct {
	// body is the payload placed inside the document element.
	body string
	// extraReference adds a second reference to an element carrying this Id.
	extraReference string
	// duplicateID repeats the referenced Id on a second element, which is the
	// classic signature wrapping primitive.
	duplicateID bool
	// omitEnveloped drops the enveloped-signature transform.
	omitEnveloped bool
	// transform overrides the reference transform algorithm.
	transform string
	// referenceURI overrides the URI of the document reference.
	referenceURI string
	// signatureParent nests the signature under this element name instead of the
	// document element.
	signatureParent string
	// duplicateSignature copies the finished signature a second time.
	duplicateSignature bool
	// corruptSignature flips the signature value after signing.
	corruptSignature bool
	// corruptDigest flips the digest of the document reference after signing.
	corruptDigest bool
}

// signDocument produces a signed Trusted List shaped document.
//
// It builds the signature the same way a real signer does — canonicalise, digest,
// sign — so the tests exercise the verifier against genuine material rather than
// recorded bytes, and negative cases can be produced precisely.
func signDocument(t testing.TB, s *signerKey, opts signOptions) []byte {
	t.Helper()

	if opts.body == "" {
		opts.body = `<SchemeInformation><TSLSequenceNumber>1</TSLSequenceNumber></SchemeInformation>`
	}

	extra := ""
	if opts.extraReference != "" {
		extra = fmt.Sprintf(`<Properties Id=%q><Note>signed properties</Note></Properties>`,
			opts.extraReference)
	}

	if opts.duplicateID {
		extra += fmt.Sprintf(`<Decoy Id=%q><Note>decoy</Note></Decoy>`, opts.extraReference)
	}

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(fmt.Sprintf(
		`<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" `+
			`xmlns:ds="http://www.w3.org/2000/09/xmldsig#">%s%s</TrustServiceStatusList>`,
		opts.body, extra)))

	root := doc.Root()

	// Build the reference list, digesting the document with the signature
	// removed exactly as the verifier will.
	transform := AlgTransformEnveloped
	if opts.transform != "" {
		transform = opts.transform
	}

	transforms := fmt.Sprintf(`<ds:Transform Algorithm=%q/>`, transform)
	if opts.omitEnveloped {
		transforms = ""
	}

	transforms += fmt.Sprintf(`<ds:Transform Algorithm=%q/>`, AlgExcC14N)

	uri := ""
	if opts.referenceURI != "" {
		uri = opts.referenceURI
	}

	c14n, err := newCanonicalizer(AlgExcC14N, nil)
	require.NoError(t, err)

	// The first reference normally covers the whole document; when a test points
	// it at a fragment instead, digest that fragment so the reference is
	// genuinely correct and the verifier fails for the reason under test.
	digestTarget := root
	if strings.HasPrefix(uri, "#") {
		digestTarget = root.FindElement("//*[@Id='" + strings.TrimPrefix(uri, "#") + "']")
		require.NotNil(t, digestTarget, "fragment %q is not in the generated document", uri)
	}

	docDigest := digestOf(c14n.canonicalize(digestTarget, nil))

	refs := fmt.Sprintf(
		`<ds:Reference URI=%q><ds:Transforms>%s</ds:Transforms>`+
			`<ds:DigestMethod Algorithm=%q/><ds:DigestValue>%s</ds:DigestValue></ds:Reference>`,
		uri, transforms, AlgDigestSHA256, docDigest)

	if opts.extraReference != "" {
		target := root.FindElement("//Properties")
		require.NotNil(t, target)

		refs += fmt.Sprintf(
			`<ds:Reference URI="#%s"><ds:Transforms><ds:Transform Algorithm=%q/></ds:Transforms>`+
				`<ds:DigestMethod Algorithm=%q/><ds:DigestValue>%s</ds:DigestValue></ds:Reference>`,
			opts.extraReference, AlgExcC14N, AlgDigestSHA256,
			digestOf(c14n.canonicalize(target, nil)))
	}

	signedInfo := fmt.Sprintf(
		`<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">`+
			`<ds:CanonicalizationMethod Algorithm=%q/>`+
			`<ds:SignatureMethod Algorithm=%q/>%s</ds:SignedInfo>`,
		AlgExcC14N, AlgRSASHA256, refs)

	// Canonicalise SignedInfo through the same code path the verifier uses.
	siDoc := etree.NewDocument()
	require.NoError(t, siDoc.ReadFromString(signedInfo))

	signed := c14n.canonicalize(siDoc.Root(), nil)

	hashed := crypto.SHA256.New()
	hashed.Write(signed)

	signature, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, hashed.Sum(nil))
	require.NoError(t, err)

	if opts.corruptSignature {
		signature[len(signature)-1] ^= 0xff
	}

	sigXML := fmt.Sprintf(
		`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">%s`+
			`<ds:SignatureValue>%s</ds:SignatureValue>`+
			`<ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate>`+
			`</ds:X509Data></ds:KeyInfo></ds:Signature>`,
		signedInfo,
		base64.StdEncoding.EncodeToString(signature),
		base64.StdEncoding.EncodeToString(s.cert.Raw))

	parent := root
	if opts.signatureParent != "" {
		nested := root.CreateElement(opts.signatureParent)
		parent = nested
	}

	attach(t, parent, sigXML)

	if opts.duplicateSignature {
		attach(t, root, sigXML)
	}

	out, err := doc.WriteToBytes()
	require.NoError(t, err)

	if opts.corruptDigest {
		out = []byte(strings.Replace(string(out), docDigest, flipBase64(docDigest), 1))
	}

	return out
}

func attach(t testing.TB, parent *etree.Element, xml string) {
	t.Helper()

	frag := etree.NewDocument()
	require.NoError(t, frag.ReadFromString(xml))
	parent.AddChild(frag.Root().Copy())
}

func digestOf(b []byte) string {
	h := crypto.SHA256.New()
	h.Write(b)

	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func flipBase64(s string) string {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) == 0 {
		return s
	}

	raw[0] ^= 0xff

	return base64.StdEncoding.EncodeToString(raw)
}

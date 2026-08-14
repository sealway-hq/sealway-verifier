// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

// Package xmldsig verifies the XML signatures that authenticate European
// Trusted Lists.
//
// It exists because no available Go implementation can verify the real lists:
// the maintained general-purpose library caps tree traversal at a size far below
// a national list, and the libraries that do handle Trusted Lists reach their
// XML layer through replace directives, which Go does not propagate to
// consumers.
//
// Only what a Trusted List legitimately uses is implemented, and everything else
// is refused rather than approximated. The package is pure Go, performs no
// input or output of its own, and returns only the content it actually
// verified, so that a caller can never interpret material the signature does not
// cover.
package xmldsig

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/beevik/etree"
)

// Signature algorithm identifiers accepted by this package.
const (
	AlgRSASHA256   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	AlgRSASHA384   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	AlgRSASHA512   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	AlgECDSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	AlgECDSASHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
	AlgECDSASHA512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"

	AlgDigestSHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
	AlgDigestSHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
	AlgDigestSHA512 = "http://www.w3.org/2001/04/xmlenc#sha512"

	AlgTransformEnveloped = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
)

// MinRSAKeyBits is the smallest RSA key accepted. Trusted List operators use
// 2048 bits or more, and anything weaker is refused rather than reported.
const MinRSAKeyBits = 2048

// Errors returned when a document cannot be verified.
var (
	// ErrNoSignature is returned when the document carries no signature.
	ErrNoSignature = errors.New("xmldsig: the document carries no signature")
	// ErrAmbiguousSignature is returned when the document carries more than one
	// signature, which makes the signed content undecidable.
	ErrAmbiguousSignature = errors.New("xmldsig: the document carries several signatures")
	// ErrUnsupportedAlgorithm is returned for an algorithm this package refuses.
	ErrUnsupportedAlgorithm = errors.New("xmldsig: unsupported algorithm")
	// ErrMalformed is returned for a document that is not well formed or whose
	// signature structure is not usable.
	ErrMalformed = errors.New("xmldsig: malformed document or signature")
	// ErrDigestMismatch is returned when a reference digest does not match.
	ErrDigestMismatch = errors.New("xmldsig: reference digest mismatch")
	// ErrSignatureInvalid is returned when the signature does not verify.
	ErrSignatureInvalid = errors.New("xmldsig: signature is not valid")
	// ErrUntrustedSigner is returned when the signing certificate is not among
	// the accepted signers.
	ErrUntrustedSigner = errors.New("xmldsig: the signing certificate is not accepted")
	// ErrLimitExceeded is returned when a document exceeds a configured limit.
	ErrLimitExceeded = errors.New("xmldsig: document exceeds a configured limit")
)

// Limits bounds the resources a hostile document can consume.
//
// A zero value selects the defaults. A national Trusted List is a few megabytes,
// so these leave headroom while still refusing an absurd document.
type Limits struct {
	MaxBytes      int64
	MaxReferences int
	MaxDepth      int
}

// Default resource limits.
const (
	DefaultMaxBytes      = 64 << 20 // 64 MiB
	DefaultMaxReferences = 64
	DefaultMaxDepth      = 500
)

func (l Limits) withDefaults() Limits {
	if l.MaxBytes <= 0 {
		l.MaxBytes = DefaultMaxBytes
	}

	if l.MaxReferences <= 0 {
		l.MaxReferences = DefaultMaxReferences
	}

	if l.MaxDepth <= 0 {
		l.MaxDepth = DefaultMaxDepth
	}

	return l
}

// Result is what a successful verification establishes.
type Result struct {
	// Signer is the certificate whose key produced the signature.
	Signer *x509.Certificate
	// Certificates are all the certificates the signature carried.
	Certificates []*x509.Certificate
	// SignedDocument is the document element as it was actually signed.
	//
	// Callers must interpret this element and nothing else: it is the only part
	// of the input the signature covers.
	SignedDocument *etree.Element
	// SignatureAlgorithm is the identifier of the algorithm used.
	SignatureAlgorithm string
	// DigestAlgorithms are the identifiers used by the verified references.
	DigestAlgorithms []string
}

// Verify checks the enveloped signature of an XML document.
//
// The signer must be one of accepted; this package never consults a system trust
// store, because the authenticity of a Trusted List comes from the authority
// that published its pointer, not from the host's opinion of the web.
//
// On success the returned Result carries the element the signature actually
// covers. A caller that interprets the original bytes instead would defeat the
// verification, which is why the verified tree is returned rather than a boolean.
func Verify(data []byte, accepted []*x509.Certificate, limits Limits) (*Result, error) {
	limits = limits.withDefaults()

	if int64(len(data)) > limits.MaxBytes {
		return nil, fmt.Errorf("%w: %d bytes exceeds the maximum of %d",
			ErrLimitExceeded, len(data), limits.MaxBytes)
	}

	doc := etree.NewDocument()
	// Nothing in a Trusted List needs an entity or a document type declaration,
	// and refusing them removes entity expansion attacks entirely.
	doc.ReadSettings.Entity = map[string]string{}
	doc.ReadSettings.Permissive = false
	doc.ReadSettings.PreserveCData = true

	if err := doc.ReadFromBytes(data); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}

	root := doc.Root()
	if root == nil {
		return nil, fmt.Errorf("%w: no document element", ErrMalformed)
	}

	if err := checkDepth(root, limits.MaxDepth); err != nil {
		return nil, err
	}

	sig, err := findSignature(root)
	if err != nil {
		return nil, err
	}

	return verifySignature(root, sig, accepted, limits)
}

// findSignature locates the single enveloped signature of the document.
//
// Several signatures make the signed content undecidable, and a signature that
// is not a child of the document element is refused: both shapes are the raw
// material of XML Signature Wrapping, where a validator checks one signature
// while a reader consumes content covered by none.
func findSignature(root *etree.Element) (*etree.Element, error) {
	var found []*etree.Element

	var walk func(el *etree.Element)

	walk = func(el *etree.Element) {
		for _, child := range el.ChildElements() {
			if child.Tag == "Signature" {
				if uri, _ := lookupPrefix(child, child.Space); uri == nsXMLDSig {
					found = append(found, child)

					continue
				}
			}

			walk(child)
		}
	}

	walk(root)

	switch len(found) {
	case 0:
		return nil, ErrNoSignature
	case 1:
	default:
		return nil, fmt.Errorf("%w: %d signatures", ErrAmbiguousSignature, len(found))
	}

	sig := found[0]
	if sig.Parent() != root {
		return nil, fmt.Errorf(
			"%w: the signature is not a direct child of the document element", ErrMalformed)
	}

	return sig, nil
}

const nsXMLDSig = "http://www.w3.org/2000/09/xmldsig#"

func verifySignature(
	root, sig *etree.Element,
	accepted []*x509.Certificate,
	limits Limits,
) (*Result, error) {
	signedInfo := childElement(sig, "SignedInfo")
	if signedInfo == nil {
		return nil, fmt.Errorf("%w: no SignedInfo", ErrMalformed)
	}

	sigMethod := childElement(signedInfo, "SignatureMethod")
	if sigMethod == nil {
		return nil, fmt.Errorf("%w: no SignatureMethod", ErrMalformed)
	}

	sigAlg := sigMethod.SelectAttrValue("Algorithm", "")

	hash, verify, err := signatureAlgorithm(sigAlg)
	if err != nil {
		return nil, err
	}

	certs, err := signatureCertificates(sig)
	if err != nil {
		return nil, err
	}

	signer, err := acceptedSigner(certs, accepted)
	if err != nil {
		return nil, err
	}

	digests, err := verifyReferences(root, sig, signedInfo, limits)
	if err != nil {
		return nil, err
	}

	// The signature is computed over the canonical form of SignedInfo, using the
	// canonicalization method SignedInfo itself declares.
	c14nMethod := childElement(signedInfo, "CanonicalizationMethod")
	if c14nMethod == nil {
		return nil, fmt.Errorf("%w: no CanonicalizationMethod", ErrMalformed)
	}

	c14n, err := newCanonicalizer(
		c14nMethod.SelectAttrValue("Algorithm", ""),
		inclusivePrefixesOf(c14nMethod),
	)
	if err != nil {
		return nil, err
	}

	signedBytes := c14n.canonicalize(signedInfo, nil)

	sigValue, err := decodeBase64Element(childElement(sig, "SignatureValue"))
	if err != nil {
		return nil, fmt.Errorf("%w: SignatureValue: %w", ErrMalformed, err)
	}

	if err := verify(signer, hash, signedBytes, sigValue); err != nil {
		return nil, err
	}

	return &Result{
		Signer:             signer,
		Certificates:       certs,
		SignedDocument:     root,
		SignatureAlgorithm: sigAlg,
		DigestAlgorithms:   digests,
	}, nil
}

// verifyReferences checks every reference of the signature.
//
// All of them must verify: a signature is only meaningful if everything it
// claims to cover really is covered, and accepting a signature with one
// unresolvable reference is how wrapping attacks succeed.
func verifyReferences(
	root, sig, signedInfo *etree.Element,
	limits Limits,
) ([]string, error) {
	refs := childElements(signedInfo, "Reference")
	if len(refs) == 0 {
		return nil, fmt.Errorf("%w: SignedInfo carries no Reference", ErrMalformed)
	}

	if len(refs) > limits.MaxReferences {
		return nil, fmt.Errorf("%w: %d references", ErrLimitExceeded, len(refs))
	}

	algorithms := make([]string, 0, len(refs))
	coversDocument := false

	for _, ref := range refs {
		uri := ref.SelectAttrValue("URI", "")

		target, isDocument, err := resolveReference(root, uri)
		if err != nil {
			return nil, err
		}

		if isDocument {
			coversDocument = true
		}

		alg, err := verifyReference(ref, target, sig, isDocument)
		if err != nil {
			return nil, err
		}

		algorithms = append(algorithms, alg)
	}

	// One reference must cover the document itself, otherwise the signature says
	// nothing about the list being validated.
	if !coversDocument {
		return nil, fmt.Errorf("%w: no reference covers the document element", ErrMalformed)
	}

	return algorithms, nil
}

// resolveReference finds the element a reference points at.
//
// Only two forms occur in a Trusted List: the empty URI, meaning the whole
// document, and a same-document fragment. External references are refused, since
// resolving them would fetch attacker-chosen material.
func resolveReference(root *etree.Element, uri string) (target *etree.Element, isDocument bool, err error) {
	switch {
	case uri == "":
		return root, true, nil
	case strings.HasPrefix(uri, "#"):
		id := uri[1:]

		found := elementsByID(root, id)
		switch len(found) {
		case 1:
			return found[0], false, nil
		case 0:
			return nil, false, fmt.Errorf("%w: reference %q resolves to nothing", ErrMalformed, uri)
		default:
			// Duplicate identifiers are the classic wrapping primitive: the
			// validator digests one element while a reader consumes another.
			return nil, false, fmt.Errorf(
				"%w: reference %q resolves to %d elements", ErrMalformed, uri, len(found))
		}
	default:
		return nil, false, fmt.Errorf(
			"%w: reference %q is not a same-document reference", ErrMalformed, uri)
	}
}

// verifyReference digests one reference target and compares it.
func verifyReference(ref, target, sig *etree.Element, isDocument bool) (string, error) {
	digestMethod := childElement(ref, "DigestMethod")
	if digestMethod == nil {
		return "", fmt.Errorf("%w: a Reference carries no DigestMethod", ErrMalformed)
	}

	alg := digestMethod.SelectAttrValue("Algorithm", "")

	hash, err := digestAlgorithm(alg)
	if err != nil {
		return "", err
	}

	expected, err := decodeBase64Element(childElement(ref, "DigestValue"))
	if err != nil {
		return "", fmt.Errorf("%w: DigestValue: %w", ErrMalformed, err)
	}

	c14n, skip, err := referenceTransforms(ref, sig, isDocument)
	if err != nil {
		return "", err
	}

	h := hash.New()
	h.Write(c14n.canonicalize(target, skip))

	if !equalDigest(h.Sum(nil), expected) {
		return "", fmt.Errorf("%w: reference %q", ErrDigestMismatch, ref.SelectAttrValue("URI", ""))
	}

	return alg, nil
}

// referenceTransforms builds the canonicalizer and the exclusion set a reference
// declares.
//
// Only the enveloped-signature transform and a canonicalization are accepted.
// Anything else, in particular XPath or XSLT, is refused: those let a signature
// select an arbitrary subset of the document, which makes what is signed
// unreviewable.
func referenceTransforms(ref, sig *etree.Element, isDocument bool) (*canonicalizer, omitted, error) {
	var (
		c14nAlgorithm = AlgC14N10
		inclusive     []string
		enveloped     bool
	)

	if transforms := childElement(ref, "Transforms"); transforms != nil {
		for _, t := range childElements(transforms, "Transform") {
			alg := t.SelectAttrValue("Algorithm", "")

			switch alg {
			case AlgTransformEnveloped:
				enveloped = true
			case AlgExcC14N, AlgExcC14NWithComments,
				AlgC14N10, AlgC14N10WithComments,
				AlgC14N11, AlgC14N11WithComments:
				c14nAlgorithm = alg
				inclusive = inclusivePrefixesOf(t)
			default:
				return nil, nil, fmt.Errorf("%w: transform %q", ErrUnsupportedAlgorithm, alg)
			}
		}
	}

	// A reference over the whole document must remove the signature from what it
	// digests, otherwise the digest could never be stable.
	if isDocument && !enveloped {
		return nil, nil, fmt.Errorf(
			"%w: a reference covering the document must apply the enveloped-signature transform",
			ErrMalformed)
	}

	c14n, err := newCanonicalizer(c14nAlgorithm, inclusive)
	if err != nil {
		return nil, nil, err
	}

	skip := omitted{}
	if enveloped {
		skip[sig] = true
	}

	return c14n, skip, nil
}

func inclusivePrefixesOf(el *etree.Element) []string {
	for _, child := range el.ChildElements() {
		if child.Tag != "InclusiveNamespaces" {
			continue
		}

		list := child.SelectAttrValue("PrefixList", "")
		if list == "" {
			return nil
		}

		return strings.Fields(list)
	}

	return nil
}

// elementsByID finds elements carrying an identifier attribute with the given
// value. Every spelling used in practice is considered, so that a duplicate
// under any of them is detected rather than ignored.
func elementsByID(root *etree.Element, id string) []*etree.Element {
	var found []*etree.Element

	var walk func(el *etree.Element)

	walk = func(el *etree.Element) {
		for _, name := range []string{"Id", "ID", "id"} {
			if el.SelectAttrValue(name, "") == id {
				found = append(found, el)

				break
			}
		}

		for _, child := range el.ChildElements() {
			walk(child)
		}
	}

	walk(root)

	return found
}

func childElement(el *etree.Element, tag string) *etree.Element {
	if el == nil {
		return nil
	}

	for _, child := range el.ChildElements() {
		if child.Tag == tag {
			return child
		}
	}

	return nil
}

func childElements(el *etree.Element, tag string) []*etree.Element {
	if el == nil {
		return nil
	}

	var out []*etree.Element

	for _, child := range el.ChildElements() {
		if child.Tag == tag {
			out = append(out, child)
		}
	}

	return out
}

func decodeBase64Element(el *etree.Element) ([]byte, error) {
	if el == nil {
		return nil, errors.New("element is absent")
	}

	return base64.StdEncoding.DecodeString(strings.Join(strings.Fields(el.Text()), ""))
}

func checkDepth(el *etree.Element, maxDepth int) error {
	var walk func(el *etree.Element, depth int) error

	walk = func(el *etree.Element, depth int) error {
		if depth > maxDepth {
			return fmt.Errorf("%w: nested deeper than %d", ErrLimitExceeded, maxDepth)
		}

		for _, child := range el.ChildElements() {
			if err := walk(child, depth+1); err != nil {
				return err
			}
		}

		return nil
	}

	return walk(el, 1)
}

func equalDigest(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}

	return diff == 0
}

// signatureAlgorithm maps an identifier to its hash and verification function.
func signatureAlgorithm(alg string) (crypto.Hash, func(*x509.Certificate, crypto.Hash, []byte, []byte) error, error) {
	var (
		hash    crypto.Hash
		x509alg x509.SignatureAlgorithm
	)

	switch alg {
	case AlgRSASHA256:
		hash, x509alg = crypto.SHA256, x509.SHA256WithRSA
	case AlgRSASHA384:
		hash, x509alg = crypto.SHA384, x509.SHA384WithRSA
	case AlgRSASHA512:
		hash, x509alg = crypto.SHA512, x509.SHA512WithRSA
	case AlgECDSASHA256:
		hash, x509alg = crypto.SHA256, x509.ECDSAWithSHA256
	case AlgECDSASHA384:
		hash, x509alg = crypto.SHA384, x509.ECDSAWithSHA384
	case AlgECDSASHA512:
		hash, x509alg = crypto.SHA512, x509.ECDSAWithSHA512
	default:
		return 0, nil, fmt.Errorf("%w: signature algorithm %q", ErrUnsupportedAlgorithm, alg)
	}

	verify := func(cert *x509.Certificate, _ crypto.Hash, signed, signature []byte) error {
		if err := cert.CheckSignature(x509alg, signed, signature); err != nil {
			return fmt.Errorf("%w: %w", ErrSignatureInvalid, err)
		}

		return nil
	}

	return hash, verify, nil
}

func digestAlgorithm(alg string) (crypto.Hash, error) {
	switch alg {
	case AlgDigestSHA256:
		return crypto.SHA256, nil
	case AlgDigestSHA384:
		return crypto.SHA384, nil
	case AlgDigestSHA512:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("%w: digest algorithm %q", ErrUnsupportedAlgorithm, alg)
	}
}

// signatureCertificates extracts the certificates carried by the signature.
func signatureCertificates(sig *etree.Element) ([]*x509.Certificate, error) {
	keyInfo := childElement(sig, "KeyInfo")
	if keyInfo == nil {
		return nil, fmt.Errorf("%w: no KeyInfo", ErrMalformed)
	}

	var out []*x509.Certificate

	for _, data := range childElements(keyInfo, "X509Data") {
		for _, el := range childElements(data, "X509Certificate") {
			der, err := decodeBase64Element(el)
			if err != nil {
				return nil, fmt.Errorf("%w: X509Certificate: %w", ErrMalformed, err)
			}

			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, fmt.Errorf("%w: X509Certificate: %w", ErrMalformed, err)
			}

			out = append(out, cert)
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("%w: KeyInfo carries no certificate", ErrMalformed)
	}

	return out, nil
}

// acceptedSigner returns the certificate that is both carried by the signature
// and accepted by the caller.
//
// Matching is on the full encoded certificate, not on a name or a serial, so a
// lookalike cannot be substituted.
func acceptedSigner(carried, accepted []*x509.Certificate) (*x509.Certificate, error) {
	if len(accepted) == 0 {
		return nil, fmt.Errorf("%w: no accepted signer was supplied", ErrUntrustedSigner)
	}

	for _, c := range carried {
		for _, a := range accepted {
			if c.Equal(a) {
				if err := checkKeyStrength(c); err != nil {
					return nil, err
				}

				return c, nil
			}
		}
	}

	return nil, ErrUntrustedSigner
}

func checkKeyStrength(cert *x509.Certificate) error {
	if key, ok := cert.PublicKey.(*rsa.PublicKey); ok && key.N.BitLen() < MinRSAKeyBits {
		return fmt.Errorf("%w: RSA key of %d bits is below the %d bit minimum",
			ErrUnsupportedAlgorithm, key.N.BitLen(), MinRSAKeyBits)
	}

	return nil
}

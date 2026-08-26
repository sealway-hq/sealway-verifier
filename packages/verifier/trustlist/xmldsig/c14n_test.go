// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package xmldsig

import (
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// canonicalizeDoc parses a document the way Verify does and canonicalises its
// root, so that what is measured here is what a signature is computed over.
func canonicalizeDoc(t *testing.T, algorithm, in string) string {
	t.Helper()

	doc := etree.NewDocument()
	doc.ReadSettings.Entity = map[string]string{}
	doc.ReadSettings.Permissive = false
	doc.ReadSettings.PreserveCData = true

	require.NoError(t, doc.ReadFromBytes([]byte(in)))
	require.NotNil(t, doc.Root())

	c, err := newCanonicalizer(algorithm, nil)
	require.NoError(t, err)

	return string(c.canonicalize(doc.Root(), nil))
}

// TestCanonicalizeMatchesAnIndependentImplementation is the test the whole
// canonicalizer rests on.
//
// Canonicalization is the security-critical half of an XML signature: the digest
// is taken over this output, so agreeing with the rest of the world is the
// property that matters, not agreeing with ourselves. The expected forms were
// therefore produced by libxml2, written independently of this code:
//
//	xmllint --c14n     input.xml
//	xmllint --exc-c14n input.xml
func TestCanonicalizeMatchesAnIndependentImplementation(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		in        string
		inclusive string
		exclusive string
	}{
		{
			// Inclusive canonicalization carries every declaration in scope, so
			// the unused urn:b survives on the root. Exclusive keeps only what is
			// used and moves the declaration down to the element that uses it.
			name:      "namespace declarations in scope",
			in:        `<root xmlns:a="urn:a" xmlns:b="urn:b"><child><a:leaf a:k="v"/></child></root>`,
			inclusive: `<root xmlns:a="urn:a" xmlns:b="urn:b"><child><a:leaf a:k="v"></a:leaf></child></root>`,
			exclusive: `<root><child><a:leaf xmlns:a="urn:a" a:k="v"></a:leaf></child></root>`,
		},
		{
			// Text and attribute values escape differently: a tab is literal in
			// text and a character reference in an attribute, and > is escaped in
			// text but not in an attribute.
			name:      "character escaping",
			in:        `<root attr="tab&#x9;lf&#xA;cr&#xD;amp&amp;lt&lt;quot&quot;">text&amp;&lt;&gt;cr&#xD;end</root>`,
			inclusive: `<root attr="tab&#x9;lf&#xA;cr&#xD;amp&amp;lt&lt;quot&quot;">text&amp;&lt;&gt;cr&#xD;end</root>`,
			exclusive: `<root attr="tab&#x9;lf&#xA;cr&#xD;amp&amp;lt&lt;quot&quot;">text&amp;&lt;&gt;cr&#xD;end</root>`,
		},
		{
			// Declarations sort by prefix and come first; then unprefixed
			// attributes by local name; then the rest by namespace URI.
			name:      "attribute ordering",
			in:        `<root xmlns:z="urn:z" xmlns:a="urn:a" z:last="4" b="2" a:mid="3" a1="1"/>`,
			inclusive: `<root xmlns:a="urn:a" xmlns:z="urn:z" a1="1" b="2" a:mid="3" z:last="4"></root>`,
			exclusive: `<root xmlns:a="urn:a" xmlns:z="urn:z" a1="1" b="2" a:mid="3" z:last="4"></root>`,
		},
		{
			// An empty default declaration is emitted, because it cancels the one
			// an ancestor put in scope and dropping it would change what the
			// child element means.
			name:      "default namespace cancelled by a child",
			in:        `<root xmlns="urn:d"><child xmlns=""><leaf/></child></root>`,
			inclusive: `<root xmlns="urn:d"><child xmlns=""><leaf></leaf></child></root>`,
			exclusive: `<root xmlns="urn:d"><child xmlns=""><leaf></leaf></child></root>`,
		},
		{
			// The xml prefix is bound implicitly and is never declared, while the
			// attributes using it are kept.
			name:      "the implicitly bound xml prefix",
			in:        `<root xml:lang="en" xmlns:p="urn:p"><p:child xml:space="preserve"/></root>`,
			inclusive: `<root xmlns:p="urn:p" xml:lang="en"><p:child xml:space="preserve"></p:child></root>`,
			exclusive: `<root xml:lang="en"><p:child xmlns:p="urn:p" xml:space="preserve"></p:child></root>`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.inclusive, canonicalizeDoc(t, AlgC14N10, tc.in), "inclusive")
			assert.Equal(t, tc.exclusive, canonicalizeDoc(t, AlgExcC14N, tc.in), "exclusive")
		})
	}
}

// TestExclusiveCanonicalizationHonoursAnInclusivePrefixList covers the escape
// hatch exclusive canonicalization provides: a prefix named by an
// InclusiveNamespaces element is carried the way inclusive canonicalization
// would carry it, even where it is not used.
func TestExclusiveCanonicalizationHonoursAnInclusivePrefixList(t *testing.T) {
	t.Parallel()

	const in = `<root xmlns:a="urn:a" xmlns:b="urn:b"><child><a:leaf a:k="v"/></child></root>`

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes([]byte(in)))

	c, err := newCanonicalizer(AlgExcC14N, []string{"b"})
	require.NoError(t, err)

	// Without the list, urn:b would be dropped as unused.
	assert.Equal(t,
		`<root xmlns:b="urn:b"><child><a:leaf xmlns:a="urn:a" a:k="v"></a:leaf></child></root>`,
		string(c.canonicalize(doc.Root(), nil)))
}

// TestInclusivePrefixListMapsTheDefaultToken pins the spelling the specification
// uses for the default namespace inside a prefix list.
func TestInclusivePrefixListMapsTheDefaultToken(t *testing.T) {
	t.Parallel()

	c, err := newCanonicalizer(AlgExcC14N, []string{"#default", "p"})
	require.NoError(t, err)

	assert.True(t, c.inclusivePrefixes[""], "#default names the default namespace")
	assert.True(t, c.inclusivePrefixes["p"])
}

// TestNewCanonicalizerRefusesAnUnknownAlgorithm keeps an unrecognised algorithm
// from being approximated: canonicalising differently from the signer computes a
// digest over something the signer never signed, which is a signature bypass
// rather than a compatibility inconvenience.
func TestNewCanonicalizerRefusesAnUnknownAlgorithm(t *testing.T) {
	t.Parallel()

	for _, alg := range []string{
		"",
		"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments-typo",
		"http://example.test/c14n",
	} {
		_, err := newCanonicalizer(alg, nil)
		require.ErrorIs(t, err, ErrUnsupportedAlgorithm, "algorithm %q", alg)
	}
}

// TestSignatureAlgorithmRefusesAnythingWeakOrUnknown pins the suite this
// verifier accepts.
//
// SHA-1 is the one that matters: it is still widely present in XML signature
// tooling, and accepting it would let a collision stand in for a signature.
func TestSignatureAlgorithmRefusesAnythingWeakOrUnknown(t *testing.T) {
	t.Parallel()

	for _, alg := range []string{
		"http://www.w3.org/2000/09/xmldsig#rsa-sha1",
		"http://www.w3.org/2000/09/xmldsig#dsa-sha1",
		"http://www.w3.org/2001/04/xmldsig-more#hmac-md5",
		"http://example.test/sign",
		"",
	} {
		_, _, err := signatureAlgorithm(alg)
		require.ErrorIs(t, err, ErrUnsupportedAlgorithm, "algorithm %q", alg)
	}

	for _, alg := range []string{
		AlgRSASHA256, AlgRSASHA384, AlgRSASHA512,
		AlgECDSASHA256, AlgECDSASHA384, AlgECDSASHA512,
	} {
		hash, verify, err := signatureAlgorithm(alg)
		require.NoError(t, err, "algorithm %q", alg)
		assert.True(t, hash.Available())
		assert.NotNil(t, verify)
	}
}

// TestDigestAlgorithmRefusesAnythingWeakOrUnknown does the same for the digest
// of a reference, which is the other half of what a signature commits to.
func TestDigestAlgorithmRefusesAnythingWeakOrUnknown(t *testing.T) {
	t.Parallel()

	for _, alg := range []string{
		"http://www.w3.org/2000/09/xmldsig#sha1",
		"http://www.w3.org/2001/04/xmldsig-more#md5",
		"http://example.test/digest",
		"",
	} {
		_, err := digestAlgorithm(alg)
		require.ErrorIs(t, err, ErrUnsupportedAlgorithm, "algorithm %q", alg)
	}

	for _, alg := range []string{AlgDigestSHA256, AlgDigestSHA384, AlgDigestSHA512} {
		hash, err := digestAlgorithm(alg)
		require.NoError(t, err, "algorithm %q", alg)
		assert.True(t, hash.Available())
	}
}

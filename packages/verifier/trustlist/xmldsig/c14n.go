// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package xmldsig

import (
	"fmt"
	"sort"
	"strings"

	"github.com/beevik/etree"
)

// Canonicalization algorithm identifiers.
const (
	// AlgExcC14N is Exclusive XML Canonicalization 1.0.
	AlgExcC14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
	// AlgExcC14NWithComments is Exclusive XML Canonicalization 1.0 with comments.
	AlgExcC14NWithComments = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
	// AlgC14N10 is Canonical XML 1.0.
	AlgC14N10 = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	// AlgC14N10WithComments is Canonical XML 1.0 with comments.
	AlgC14N10WithComments = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
	// AlgC14N11 is Canonical XML 1.1.
	AlgC14N11 = "http://www.w3.org/2006/12/xml-c14n11"
	// AlgC14N11WithComments is Canonical XML 1.1 with comments.
	AlgC14N11WithComments = "http://www.w3.org/2006/12/xml-c14n11#WithComments"
)

const (
	xmlnsPrefix = "xmlns"
	xmlPrefix   = "xml"
	xmlNS       = "http://www.w3.org/XML/1998/namespace"
)

// canonicalizer serialises an element according to a canonicalization
// algorithm.
//
// Canonicalization is the security-critical half of an XML signature: the digest
// is taken over this output, so any disagreement between what is canonicalised
// and what a reader later interprets is a signature bypass. It therefore works
// from the parsed tree, and the tree preserves the prefixes exactly as written,
// because the canonical form is defined in terms of them.
type canonicalizer struct {
	// exclusive selects Exclusive XML Canonicalization, where an element only
	// carries the namespaces it actually uses.
	exclusive bool
	// withComments keeps comment nodes in the output.
	withComments bool
	// inclusivePrefixes are prefixes an exclusive canonicalization must treat as
	// inclusive, as listed by an InclusiveNamespaces element.
	inclusivePrefixes map[string]bool
}

// newCanonicalizer returns the canonicalizer for an algorithm identifier.
//
// An unknown algorithm is refused rather than approximated: canonicalising
// differently from the signer would compute a digest over something the signer
// never signed.
func newCanonicalizer(algorithm string, inclusivePrefixes []string) (*canonicalizer, error) {
	c := &canonicalizer{inclusivePrefixes: map[string]bool{}}

	for _, p := range inclusivePrefixes {
		if p == "#default" {
			p = ""
		}

		c.inclusivePrefixes[p] = true
	}

	switch algorithm {
	case AlgExcC14N:
		c.exclusive = true
	case AlgExcC14NWithComments:
		c.exclusive, c.withComments = true, true
	case AlgC14N10, AlgC14N11:
	case AlgC14N10WithComments, AlgC14N11WithComments:
		c.withComments = true
	default:
		return nil, fmt.Errorf("%w: canonicalization algorithm %q", ErrUnsupportedAlgorithm, algorithm)
	}

	return c, nil
}

// omitted reports elements excluded from the node set, which is how the
// enveloped-signature transform removes the signature from what is digested.
type omitted map[*etree.Element]bool

// canonicalize serialises the subtree rooted at el.
func (c *canonicalizer) canonicalize(el *etree.Element, skip omitted) []byte {
	var b strings.Builder

	c.writeElement(&b, el, skip, map[string]string{})

	return []byte(b.String())
}

// writeElement emits one element and its descendants.
//
// rendered maps a prefix to the namespace URI an output ancestor already
// emitted for it, so a declaration is only repeated when it changes.
func (c *canonicalizer) writeElement(
	b *strings.Builder,
	el *etree.Element,
	skip omitted,
	rendered map[string]string,
) {
	if skip[el] {
		return
	}

	decls := c.visibleNamespaces(el, rendered)

	child := make(map[string]string, len(rendered)+len(decls))
	for k, v := range rendered {
		child[k] = v
	}

	for _, d := range decls {
		child[d.prefix] = d.uri
	}

	name := qname(el.Space, el.Tag)

	b.WriteString("<")
	b.WriteString(name)

	for _, d := range decls {
		b.WriteString(" ")

		if d.prefix == "" {
			b.WriteString(xmlnsPrefix)
		} else {
			b.WriteString(xmlnsPrefix + ":")
			b.WriteString(d.prefix)
		}

		b.WriteString(`="`)
		b.WriteString(escapeAttr(d.uri))
		b.WriteString(`"`)
	}

	for _, a := range c.orderedAttributes(el) {
		b.WriteString(" ")
		b.WriteString(qname(a.Space, a.Key))
		b.WriteString(`="`)
		b.WriteString(escapeAttr(a.Value))
		b.WriteString(`"`)
	}

	b.WriteString(">")

	for _, tok := range el.Child {
		switch t := tok.(type) {
		case *etree.Element:
			c.writeElement(b, t, skip, child)
		case *etree.CharData:
			// Canonical XML has no CDATA sections: their content is emitted as
			// ordinary escaped text.
			b.WriteString(escapeText(t.Data))
		case *etree.Comment:
			if c.withComments {
				b.WriteString("<!--")
				b.WriteString(t.Data)
				b.WriteString("-->")
			}
		case *etree.ProcInst:
			b.WriteString("<?")
			b.WriteString(t.Target)

			if t.Inst != "" {
				b.WriteString(" ")
				b.WriteString(t.Inst)
			}

			b.WriteString("?>")
		}
	}

	b.WriteString("</")
	b.WriteString(name)
	b.WriteString(">")
}

// visibleNamespaces returns the declarations this element must carry, sorted by
// prefix.
//
// This is where exclusive and inclusive canonicalization differ, and it is what
// attackers probe: under exclusive canonicalization an element carries only the
// namespaces it or its attributes actually use, so relocating a subtree cannot
// silently change its meaning.
func (c *canonicalizer) visibleNamespaces(el *etree.Element, rendered map[string]string) []nsDecl {
	wanted := map[string]bool{}

	if c.exclusive {
		wanted[el.Space] = true

		for _, a := range el.Attr {
			if !isNamespaceDecl(a) && a.Space != "" {
				wanted[a.Space] = true
			}
		}

		for p := range c.inclusivePrefixes {
			wanted[p] = true
		}
	} else {
		for _, d := range inScopeDeclarations(el) {
			wanted[d.prefix] = true
		}
	}

	out := make([]nsDecl, 0, len(wanted))

	for prefix := range wanted {
		if prefix == xmlPrefix {
			continue // the xml prefix is implicitly bound and never declared
		}

		uri, bound := lookupPrefix(el, prefix)
		if !bound {
			continue
		}

		previous, seen := rendered[prefix]
		if seen && previous == uri {
			continue
		}

		// An undeclared default namespace is only emitted to cancel one an
		// ancestor put in scope.
		if prefix == "" && uri == "" && !seen {
			continue
		}

		out = append(out, nsDecl{prefix: prefix, uri: uri})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].prefix < out[j].prefix })

	return out
}

// orderedAttributes returns the non-namespace attributes in canonical order:
// unprefixed ones first by local name, then the rest by namespace URI and local
// name.
func (c *canonicalizer) orderedAttributes(el *etree.Element) []etree.Attr {
	out := make([]etree.Attr, 0, len(el.Attr))

	for _, a := range el.Attr {
		if !isNamespaceDecl(a) {
			out = append(out, a)
		}
	}

	uriOf := func(a etree.Attr) string {
		if a.Space == "" {
			return ""
		}

		uri, _ := lookupPrefix(el, a.Space)

		return uri
	}

	sort.SliceStable(out, func(i, j int) bool {
		ui, uj := uriOf(out[i]), uriOf(out[j])
		if (ui == "") != (uj == "") {
			return ui == ""
		}

		if ui != uj {
			return ui < uj
		}

		return out[i].Key < out[j].Key
	})

	return out
}

type nsDecl struct {
	prefix string
	uri    string
}

func qname(space, local string) string {
	if space == "" {
		return local
	}

	return space + ":" + local
}

// isNamespaceDecl reports whether an attribute declares a namespace.
func isNamespaceDecl(a etree.Attr) bool {
	return a.Space == xmlnsPrefix || (a.Space == "" && a.Key == xmlnsPrefix)
}

// lookupPrefix resolves a prefix against an element and its ancestors.
func lookupPrefix(el *etree.Element, prefix string) (string, bool) {
	if prefix == xmlPrefix {
		return xmlNS, true
	}

	for cur := el; cur != nil; cur = cur.Parent() {
		for _, a := range cur.Attr {
			if !isNamespaceDecl(a) {
				continue
			}

			if prefix == "" && a.Space == "" && a.Key == xmlnsPrefix {
				return a.Value, true
			}

			if prefix != "" && a.Space == xmlnsPrefix && a.Key == prefix {
				return a.Value, true
			}
		}
	}

	if prefix == "" {
		return "", true // no default namespace in scope
	}

	return "", false
}

// inScopeDeclarations returns every declaration visible from an element, nearest
// declaration of a prefix winning.
func inScopeDeclarations(el *etree.Element) []nsDecl {
	seen := map[string]bool{}

	var out []nsDecl

	for cur := el; cur != nil; cur = cur.Parent() {
		for _, a := range cur.Attr {
			if !isNamespaceDecl(a) {
				continue
			}

			prefix := a.Key
			if a.Space == "" {
				prefix = ""
			}

			if seen[prefix] {
				continue
			}

			seen[prefix] = true

			out = append(out, nsDecl{prefix: prefix, uri: a.Value})
		}
	}

	return out
}

// escapeText escapes a text node as canonical XML requires.
func escapeText(s string) string {
	var b strings.Builder

	for i := range len(s) {
		switch s[i] {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '\r':
			b.WriteString("&#xD;")
		default:
			b.WriteByte(s[i])
		}
	}

	return b.String()
}

// escapeAttr escapes an attribute value as canonical XML requires.
func escapeAttr(s string) string {
	var b strings.Builder

	for i := range len(s) {
		switch s[i] {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '"':
			b.WriteString("&quot;")
		case '\t':
			b.WriteString("&#x9;")
		case '\n':
			b.WriteString("&#xA;")
		case '\r':
			b.WriteString("&#xD;")
		default:
			b.WriteByte(s[i])
		}
	}

	return b.String()
}

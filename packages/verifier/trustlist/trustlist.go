// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

// Package trustlist reads European Trusted Lists as defined by ETSI TS 119 612.
//
// A list is only ever read after its signature has been verified, and only the
// verified tree is parsed, so nothing this package returns can come from
// material the signature does not cover.
//
// The package is pure data handling: it performs no input or output of its own
// and reaches no network, so the same code runs from a command line tool, a
// desktop application and a browser build.
package trustlist

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/beevik/etree"

	"github.com/sealway-hq/sealway-verifier/packages/verifier/trustlist/xmldsig"
)

// TSLNamespace is the XML namespace of the Trusted List schema.
const TSLNamespace = "http://uri.etsi.org/02231/v2#"

// List type identifiers.
const (
	// TypeLOTL identifies the European List of Trusted Lists.
	TypeLOTL = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists"
	// TypeGeneric identifies a national Trusted List.
	TypeGeneric = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric"
)

// Service type identifiers relevant to timestamping.
const (
	// ServiceTypeQTST is a qualified electronic timestamp service. It is the
	// only service type that can make a timestamp qualified.
	ServiceTypeQTST = "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST"
	// ServiceTypeTSA is a timestamping service that is not, by itself,
	// qualified.
	ServiceTypeTSA = "http://uri.etsi.org/TrstSvc/Svctype/TSA"
	// ServiceTypeTSAQualified is the pre-eIDAS spelling still found in some
	// lists for a qualified timestamping service.
	ServiceTypeTSAQualified = "http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-QC"
)

// Service status identifiers.
const (
	// StatusGranted means the service is recognised as qualified.
	StatusGranted = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
	// StatusWithdrawn means the recognition was withdrawn.
	StatusWithdrawn = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn"
	// StatusUnderSupervision is a pre-eIDAS status meaning supervised.
	StatusUnderSupervision = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision"
	// StatusAccredited is a pre-eIDAS status meaning accredited.
	StatusAccredited = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accredited" //nolint:gosec // an ETSI status identifier, not a credential
	// StatusSupervisionInCessation is a pre-eIDAS transitional status.
	StatusSupervisionInCessation = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionincessation"
)

// Errors returned when a list cannot be read.
var (
	// ErrNotATrustedList is returned when the document is not a Trusted List.
	ErrNotATrustedList = errors.New("trustlist: the document is not a Trusted List")
	// ErrMalformed is returned when a required part of the list is unusable.
	ErrMalformed = errors.New("trustlist: malformed Trusted List")
)

// List is an authenticated Trusted List.
type List struct {
	// Type is the TSL type identifier, telling a list of lists from a national
	// list.
	Type string
	// Territory is the scheme territory, such as "ES", or "EU" for the list of
	// lists.
	Territory string
	// SequenceNumber increases with every issue of a list. A number lower than
	// one already seen is a rollback.
	SequenceNumber uint64
	// IssueDate is when the list was issued.
	IssueDate time.Time
	// NextUpdate is when the operator undertakes to publish again. A list read
	// after this instant is stale, which is a reason to be indeterminate rather
	// than to fail.
	NextUpdate time.Time
	// Pointers are the national lists a list of lists points at.
	Pointers []Pointer
	// Providers are the trust service providers of a national list.
	Providers []Provider
	// Signer is the certificate that signed the list.
	Signer *x509.Certificate
}

// Pointer references a national list from the list of lists.
type Pointer struct {
	// Territory is the scheme territory of the pointed list.
	Territory string
	// Location is where the pointed list is published.
	Location string
	// MIMEType distinguishes the machine readable list from its human readable
	// rendering.
	MIMEType string
	// Type is the TSL type of the pointed list.
	Type string
	// SigningCertificates are the certificates allowed to sign the pointed
	// list. They are what makes the chain of authentication work: the authority
	// that publishes the pointer decides who may sign what it points at.
	SigningCertificates []*x509.Certificate
}

// Provider is a trust service provider.
type Provider struct {
	Name      string
	TradeName string
	Services  []Service
}

// Service is one trust service of a provider.
type Service struct {
	// Name is the service name as published.
	Name string
	// Type is the service type identifier.
	Type string
	// Status is the current status identifier.
	Status string
	// StatusStartingTime is when the current status took effect.
	StatusStartingTime time.Time
	// DigitalIdentities identify the service. An identity is often the issuing
	// authority rather than an end certificate, which is why a caller must match
	// a whole certification path against them.
	DigitalIdentities []Identity
	// History carries the previous statuses, which is what makes it possible to
	// answer what the status was at a past instant.
	History []HistoryEntry
}

// HistoryEntry is a previous status of a service.
type HistoryEntry struct {
	Type               string
	Status             string
	StatusStartingTime time.Time
	DigitalIdentities  []Identity
}

// Identity is a digital identity of a service.
type Identity struct {
	// Certificate is the certificate identifying the service, when the identity
	// carries one.
	Certificate *x509.Certificate
	// SubjectName is the subject distinguished name, when published on its own.
	SubjectName string
	// SubjectKeyIdentifier is the key identifier, when published on its own.
	SubjectKeyIdentifier []byte
}

// Parse reads a Trusted List from a verified document.
//
// The element must come from xmldsig.Verify: parsing anything else would read
// material no signature covers.
func Parse(verified *xmldsig.Result) (*List, error) {
	if verified == nil || verified.SignedDocument == nil {
		return nil, ErrNotATrustedList
	}

	root := verified.SignedDocument
	if root.Tag != "TrustServiceStatusList" {
		return nil, fmt.Errorf("%w: document element is %q", ErrNotATrustedList, root.Tag)
	}

	// The document element must be in the Trusted List namespace. Everything
	// below is then matched by local name, which is safe because the whole tree
	// was signed by the scheme operator.
	if ns := namespaceOf(root); ns != TSLNamespace {
		return nil, fmt.Errorf("%w: document element is in the namespace %q", ErrNotATrustedList, ns)
	}

	list := &List{Signer: verified.Signer}

	info := child(root, "SchemeInformation")
	if info == nil {
		return nil, fmt.Errorf("%w: no SchemeInformation", ErrMalformed)
	}

	list.Type = text(child(info, "TSLType"))
	list.Territory = text(child(info, "SchemeTerritory"))

	if n := text(child(info, "TSLSequenceNumber")); n != "" {
		seq, err := strconv.ParseUint(strings.TrimSpace(n), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: TSLSequenceNumber %q", ErrMalformed, n)
		}

		list.SequenceNumber = seq
	}

	if t, err := parseTime(text(child(info, "ListIssueDateTime"))); err == nil {
		list.IssueDate = t
	}

	if next := child(info, "NextUpdate"); next != nil {
		if t, err := parseTime(text(child(next, "dateTime"))); err == nil {
			list.NextUpdate = t
		}
	}

	list.Pointers = parsePointers(info)
	list.Providers = parseProviders(root)

	return list, nil
}

// IsListOfLists reports whether the list points at other lists rather than
// describing services itself.
func (l *List) IsListOfLists() bool { return l.Type == TypeLOTL }

// Stale reports whether the list was read after the operator undertook to
// publish a new one.
func (l *List) Stale(at time.Time) bool {
	return !l.NextUpdate.IsZero() && at.After(l.NextUpdate)
}

// PointerFor returns the machine readable pointer for a territory.
func (l *List) PointerFor(territory string) (Pointer, bool) {
	for _, p := range l.Pointers {
		if !strings.EqualFold(p.Territory, territory) {
			continue
		}

		// A territory is published both as XML and as a human readable
		// rendering; only the machine readable one is usable.
		if strings.Contains(strings.ToLower(p.MIMEType), "xml") ||
			strings.HasSuffix(strings.ToLower(p.Location), ".xml") {
			return p, true
		}
	}

	return Pointer{}, false
}

func parsePointers(info *etree.Element) []Pointer {
	var out []Pointer

	pointers := child(info, "PointersToOtherTSL")
	if pointers == nil {
		return nil
	}

	for _, p := range children(pointers, "OtherTSLPointer") {
		ptr := Pointer{Location: text(child(p, "TSLLocation"))}

		if extra := child(p, "AdditionalInformation"); extra != nil {
			for _, other := range children(extra, "OtherInformation") {
				if t := child(other, "SchemeTerritory"); t != nil {
					ptr.Territory = text(t)
				}

				if m := child(other, "MimeType"); m != nil {
					ptr.MIMEType = text(m)
				}

				if ty := child(other, "TSLType"); ty != nil {
					ptr.Type = text(ty)
				}
			}
		}

		if si := child(p, "ServiceDigitalIdentities"); si != nil {
			for _, id := range children(si, "ServiceDigitalIdentity") {
				for _, ident := range parseIdentities(id) {
					if ident.Certificate != nil {
						ptr.SigningCertificates = append(ptr.SigningCertificates, ident.Certificate)
					}
				}
			}
		}

		out = append(out, ptr)
	}

	return out
}

func parseProviders(root *etree.Element) []Provider {
	list := child(root, "TrustServiceProviderList")
	if list == nil {
		return nil
	}

	var out []Provider

	for _, tsp := range children(list, "TrustServiceProvider") {
		p := Provider{}

		if info := child(tsp, "TSPInformation"); info != nil {
			p.Name = firstName(child(info, "TSPName"))
			p.TradeName = firstName(child(info, "TSPTradeName"))
		}

		if services := child(tsp, "TSPServices"); services != nil {
			for _, svc := range children(services, "TSPService") {
				if s, ok := parseService(svc); ok {
					p.Services = append(p.Services, s)
				}
			}
		}

		out = append(out, p)
	}

	return out
}

func parseService(svc *etree.Element) (Service, bool) {
	info := child(svc, "ServiceInformation")
	if info == nil {
		return Service{}, false
	}

	s := Service{
		Name:              firstName(child(info, "ServiceName")),
		Type:              text(child(info, "ServiceTypeIdentifier")),
		Status:            text(child(info, "ServiceStatus")),
		DigitalIdentities: parseIdentities(child(info, "ServiceDigitalIdentity")),
	}

	if t, err := parseTime(text(child(info, "StatusStartingTime"))); err == nil {
		s.StatusStartingTime = t
	}

	if history := child(svc, "ServiceHistory"); history != nil {
		for _, inst := range children(history, "ServiceHistoryInstance") {
			e := HistoryEntry{
				Type:              text(child(inst, "ServiceTypeIdentifier")),
				Status:            text(child(inst, "ServiceStatus")),
				DigitalIdentities: parseIdentities(child(inst, "ServiceDigitalIdentity")),
			}

			if t, err := parseTime(text(child(inst, "StatusStartingTime"))); err == nil {
				e.StatusStartingTime = t
			}

			s.History = append(s.History, e)
		}
	}

	return s, true
}

// parseIdentities reads the digital identities of a service.
func parseIdentities(el *etree.Element) []Identity {
	if el == nil {
		return nil
	}

	var out []Identity

	// A ServiceDigitalIdentity holds DigitalId children; a
	// ServiceDigitalIdentities holds ServiceDigitalIdentity children.
	digitalIDs := children(el, "DigitalId")
	if len(digitalIDs) == 0 {
		for _, nested := range children(el, "ServiceDigitalIdentity") {
			out = append(out, parseIdentities(nested)...)
		}

		return out
	}

	ident := Identity{}

	for _, d := range digitalIDs {
		if certEl := child(d, "X509Certificate"); certEl != nil {
			if der, err := decodeBase64(text(certEl)); err == nil {
				if cert, err := x509.ParseCertificate(der); err == nil {
					ident.Certificate = cert
				}
			}
		}

		if nameEl := child(d, "X509SubjectName"); nameEl != nil {
			ident.SubjectName = text(nameEl)
		}

		if skiEl := child(d, "X509SKI"); skiEl != nil {
			if ski, err := decodeBase64(text(skiEl)); err == nil {
				ident.SubjectKeyIdentifier = ski
			}
		}
	}

	if ident.Certificate != nil || ident.SubjectName != "" || len(ident.SubjectKeyIdentifier) > 0 {
		out = append(out, ident)
	}

	return out
}

// StatusAt returns the status of the service in effect at an instant, together
// with when that status took effect.
//
// This is what makes a past timestamp answerable: a service whose recognition
// was withdrawn today may well have been granted when the timestamp was
// produced, and reading only the current status would answer the wrong
// question.
//
// It reports false when the instant precedes everything the list records, in
// which case nothing is known rather than nothing being true.
func (s Service) StatusAt(at time.Time) (status string, since time.Time, known bool) {
	type entry struct {
		status string
		from   time.Time
	}

	timeline := make([]entry, 0, len(s.History)+1)

	for _, h := range s.History {
		if h.Status != "" && !h.StatusStartingTime.IsZero() {
			timeline = append(timeline, entry{status: h.Status, from: h.StatusStartingTime})
		}
	}

	if s.Status != "" && !s.StatusStartingTime.IsZero() {
		timeline = append(timeline, entry{status: s.Status, from: s.StatusStartingTime})
	}

	if len(timeline) == 0 {
		return "", time.Time{}, false
	}

	sort.SliceStable(timeline, func(i, j int) bool { return timeline[i].from.Before(timeline[j].from) })

	best := -1

	for i, e := range timeline {
		if !e.from.After(at) {
			best = i
		}
	}

	if best < 0 {
		return "", time.Time{}, false
	}

	return timeline[best].status, timeline[best].from, true
}

// IdentitiesAt returns the digital identities that identified the service at an
// instant, falling back to the current ones when history carries none.
func (s Service) IdentitiesAt(at time.Time) []Identity {
	var (
		best  []Identity
		since time.Time
		found bool
	)

	for _, h := range s.History {
		if h.StatusStartingTime.IsZero() || h.StatusStartingTime.After(at) {
			continue
		}

		if len(h.DigitalIdentities) == 0 {
			continue
		}

		if !found || h.StatusStartingTime.After(since) {
			best, since, found = h.DigitalIdentities, h.StatusStartingTime, true
		}
	}

	if !s.StatusStartingTime.IsZero() && !s.StatusStartingTime.After(at) &&
		len(s.DigitalIdentities) > 0 && (!found || !s.StatusStartingTime.Before(since)) {
		return s.DigitalIdentities
	}

	if found {
		return best
	}

	return s.DigitalIdentities
}

// Qualified reports whether a status identifier means the service is recognised
// as qualified.
func Qualified(status string) bool {
	switch status {
	case StatusGranted, StatusAccredited, StatusUnderSupervision:
		return true
	default:
		return false
	}
}

// TimestampService reports whether a service type identifier designates a
// timestamping service capable of producing qualified timestamps.
func TimestampService(serviceType string) bool {
	switch serviceType {
	case ServiceTypeQTST, ServiceTypeTSAQualified:
		return true
	default:
		return false
	}
}

// namespaceOf resolves the namespace an element belongs to.
func namespaceOf(el *etree.Element) string {
	for cur := el; cur != nil; cur = cur.Parent() {
		for _, a := range cur.Attr {
			switch {
			case el.Space == "" && a.Space == "" && a.Key == "xmlns":
				return a.Value
			case el.Space != "" && a.Space == "xmlns" && a.Key == el.Space:
				return a.Value
			}
		}
	}

	return ""
}

func child(el *etree.Element, tag string) *etree.Element {
	if el == nil {
		return nil
	}

	for _, c := range el.ChildElements() {
		if c.Tag == tag {
			return c
		}
	}

	return nil
}

func children(el *etree.Element, tag string) []*etree.Element {
	if el == nil {
		return nil
	}

	var out []*etree.Element

	for _, c := range el.ChildElements() {
		if c.Tag == tag {
			out = append(out, c)
		}
	}

	return out
}

func text(el *etree.Element) string {
	if el == nil {
		return ""
	}

	return strings.TrimSpace(el.Text())
}

// firstName returns the first published name of a multilingual name element.
func firstName(el *etree.Element) string {
	if el == nil {
		return ""
	}

	// An English name is preferred when present, otherwise the first one.
	fallback := ""

	for _, n := range children(el, "Name") {
		if strings.EqualFold(n.SelectAttrValue("lang", ""), "en") {
			return text(n)
		}

		if fallback == "" {
			fallback = text(n)
		}
	}

	return fallback
}

func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
}

// parseTime reads the date and time formats a Trusted List uses.
func parseTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, errors.New("empty")
	}

	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}

	return time.Time{}, fmt.Errorf("%w: unusable time %q", ErrMalformed, s)
}

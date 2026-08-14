// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package prooftest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"
)

// Trusted List identifiers used by the generated lists.
const (
	TypeLOTL    = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists"
	TypeGeneric = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric"

	ServiceTypeQTST = "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST"
	ServiceTypeTSA  = "http://uri.etsi.org/TrstSvc/Svctype/TSA"

	StatusGranted   = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
	StatusWithdrawn = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn"
)

// TrustScheme is a throwaway European trust scheme: an operator signing the list
// of lists, and one signing a national list.
type TrustScheme struct {
	// LOTLSigner signs the list of lists.
	LOTLSigner *SchemeKey
	// ListSigner signs the national list.
	ListSigner *SchemeKey
	// Territory is the scheme territory of the national list.
	Territory string
}

// SchemeKey is a signing identity of a trust scheme.
type SchemeKey struct {
	Certificate *x509.Certificate
	Key         *rsa.PrivateKey
}

// NewTrustScheme builds a throwaway trust scheme for a territory.
func NewTrustScheme(territory string) (*TrustScheme, error) {
	lotl, err := newSchemeKey("Test List of Lists Operator")
	if err != nil {
		return nil, err
	}

	list, err := newSchemeKey("Test " + territory + " Scheme Operator")
	if err != nil {
		return nil, err
	}

	return &TrustScheme{LOTLSigner: lotl, ListSigner: list, Territory: territory}, nil
}

func newSchemeKey(commonName string) (*SchemeKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2035, time.January, 1, 0, 0, 0, 0, time.UTC),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	return &SchemeKey{Certificate: cert, Key: key}, nil
}

// TrustService describes one service of a generated national list.
type TrustService struct {
	// ProviderName is the trust service provider.
	ProviderName string
	// ServiceName is the service as published.
	ServiceName string
	// Type is the service type identifier. It defaults to a qualified
	// timestamping service.
	Type string
	// Identity is the certificate the list publishes as the service identity.
	// It is normally the authority that issues the signing certificates.
	Identity *x509.Certificate
	// Status is the current status identifier.
	Status string
	// StatusSince is when the current status took effect.
	StatusSince time.Time
	// History are previous statuses, oldest first.
	History []TrustServiceHistory
}

// TrustServiceHistory is a previous status of a generated service.
type TrustServiceHistory struct {
	Status      string
	StatusSince time.Time
	Identity    *x509.Certificate
}

// TrustListOptions configures a generated national list.
type TrustListOptions struct {
	// Services are the services the list publishes.
	Services []TrustService
	// SequenceNumber is the list sequence number.
	SequenceNumber uint64
	// IssueDate is when the list was issued.
	IssueDate time.Time
	// NextUpdate is when the operator undertakes to publish again.
	NextUpdate time.Time
	// CorruptSignature invalidates the signature after signing.
	CorruptSignature bool
	// Territory overrides the declared scheme territory.
	Territory string
}

// LOTLOptions configures a generated list of lists.
type LOTLOptions struct {
	// ListLocation is where the national list is published.
	ListLocation string
	// SigningCertificates are the certificates the list of lists pins as
	// allowed to sign the national list. It defaults to the scheme list signer.
	SigningCertificates []*x509.Certificate
	// SequenceNumber is the list sequence number.
	SequenceNumber uint64
	// IssueDate is when the list was issued.
	IssueDate time.Time
	// NextUpdate is when the operator undertakes to publish again.
	NextUpdate time.Time
	// CorruptSignature invalidates the signature after signing.
	CorruptSignature bool
	// OmitPointer leaves out the pointer to the national list.
	OmitPointer bool
	// OmitSigningCertificates publishes the pointer without pinning a signer.
	OmitSigningCertificates bool
}

// LOTL builds a signed European List of Trusted Lists.
func (s *TrustScheme) LOTL(opts LOTLOptions) ([]byte, error) {
	if opts.ListLocation == "" {
		opts.ListLocation = "https://trusted-list.test/" + strings.ToLower(s.Territory) + ".xml"
	}

	if opts.SequenceNumber == 0 {
		opts.SequenceNumber = 1
	}

	if opts.IssueDate.IsZero() {
		opts.IssueDate = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	}

	if opts.NextUpdate.IsZero() {
		opts.NextUpdate = time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)
	}

	certs := opts.SigningCertificates
	if certs == nil && !opts.OmitSigningCertificates {
		certs = []*x509.Certificate{s.ListSigner.Certificate}
	}

	var pointers strings.Builder

	if !opts.OmitPointer {
		pointers.WriteString("<PointersToOtherTSL><OtherTSLPointer>")

		if len(certs) > 0 {
			pointers.WriteString("<ServiceDigitalIdentities>")

			for _, c := range certs {
				pointers.WriteString("<ServiceDigitalIdentity><DigitalId><X509Certificate>")
				pointers.WriteString(base64.StdEncoding.EncodeToString(c.Raw))
				pointers.WriteString("</X509Certificate></DigitalId></ServiceDigitalIdentity>")
			}

			pointers.WriteString("</ServiceDigitalIdentities>")
		}

		fmt.Fprintf(&pointers,
			"<TSLLocation>%s</TSLLocation>"+
				"<AdditionalInformation>"+
				"<OtherInformation><SchemeTerritory>%s</SchemeTerritory></OtherInformation>"+
				"<OtherInformation><MimeType>application/vnd.etsi.tsl+xml</MimeType></OtherInformation>"+
				"<OtherInformation><TSLType>%s</TSLType></OtherInformation>"+
				"</AdditionalInformation>",
			escapeXML(opts.ListLocation), escapeXML(s.Territory), TypeGeneric)

		pointers.WriteString("</OtherTSLPointer></PointersToOtherTSL>")
	}

	body := fmt.Sprintf(
		"<SchemeInformation><TSLType>%s</TSLType><SchemeTerritory>EU</SchemeTerritory>"+
			"<TSLSequenceNumber>%d</TSLSequenceNumber>"+
			"<ListIssueDateTime>%s</ListIssueDateTime>"+
			"<NextUpdate><dateTime>%s</dateTime></NextUpdate>%s</SchemeInformation>",
		TypeLOTL, opts.SequenceNumber,
		opts.IssueDate.UTC().Format(time.RFC3339),
		opts.NextUpdate.UTC().Format(time.RFC3339),
		pointers.String())

	return signList(body, s.LOTLSigner, opts.CorruptSignature)
}

// TrustList builds a signed national Trusted List.
func (s *TrustScheme) TrustList(opts TrustListOptions) ([]byte, error) {
	if opts.SequenceNumber == 0 {
		opts.SequenceNumber = 1
	}

	if opts.IssueDate.IsZero() {
		opts.IssueDate = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	}

	if opts.NextUpdate.IsZero() {
		opts.NextUpdate = time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)
	}

	territory := opts.Territory
	if territory == "" {
		territory = s.Territory
	}

	var providers strings.Builder

	providers.WriteString("<TrustServiceProviderList>")

	for _, svc := range opts.Services {
		providers.WriteString(renderService(svc))
	}

	providers.WriteString("</TrustServiceProviderList>")

	body := fmt.Sprintf(
		"<SchemeInformation><TSLType>%s</TSLType><SchemeTerritory>%s</SchemeTerritory>"+
			"<TSLSequenceNumber>%d</TSLSequenceNumber>"+
			"<ListIssueDateTime>%s</ListIssueDateTime>"+
			"<NextUpdate><dateTime>%s</dateTime></NextUpdate></SchemeInformation>%s",
		TypeGeneric, escapeXML(territory), opts.SequenceNumber,
		opts.IssueDate.UTC().Format(time.RFC3339),
		opts.NextUpdate.UTC().Format(time.RFC3339),
		providers.String())

	return signList(body, s.ListSigner, opts.CorruptSignature)
}

func renderService(svc TrustService) string {
	if svc.Type == "" {
		svc.Type = ServiceTypeQTST
	}

	if svc.Status == "" {
		svc.Status = StatusGranted
	}

	if svc.StatusSince.IsZero() {
		svc.StatusSince = time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
	}

	var history strings.Builder

	if len(svc.History) > 0 {
		history.WriteString("<ServiceHistory>")

		for _, h := range svc.History {
			identity := h.Identity
			if identity == nil {
				identity = svc.Identity
			}

			fmt.Fprintf(&history,
				"<ServiceHistoryInstance><ServiceTypeIdentifier>%s</ServiceTypeIdentifier>"+
					"<ServiceName><Name xml:lang=\"en\">%s</Name></ServiceName>%s"+
					"<ServiceStatus>%s</ServiceStatus>"+
					"<StatusStartingTime>%s</StatusStartingTime></ServiceHistoryInstance>",
				svc.Type, escapeXML(svc.ServiceName), renderIdentity(identity),
				h.Status, h.StatusSince.UTC().Format(time.RFC3339))
		}

		history.WriteString("</ServiceHistory>")
	}

	return fmt.Sprintf(
		"<TrustServiceProvider><TSPInformation>"+
			"<TSPName><Name xml:lang=\"en\">%s</Name></TSPName></TSPInformation>"+
			"<TSPServices><TSPService><ServiceInformation>"+
			"<ServiceTypeIdentifier>%s</ServiceTypeIdentifier>"+
			"<ServiceName><Name xml:lang=\"en\">%s</Name></ServiceName>%s"+
			"<ServiceStatus>%s</ServiceStatus>"+
			"<StatusStartingTime>%s</StatusStartingTime>"+
			"</ServiceInformation>%s</TSPService></TSPServices></TrustServiceProvider>",
		escapeXML(svc.ProviderName), svc.Type, escapeXML(svc.ServiceName),
		renderIdentity(svc.Identity), svc.Status,
		svc.StatusSince.UTC().Format(time.RFC3339), history.String())
}

func renderIdentity(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}

	return "<ServiceDigitalIdentity><DigitalId><X509Certificate>" +
		base64.StdEncoding.EncodeToString(cert.Raw) +
		"</X509Certificate></DigitalId></ServiceDigitalIdentity>"
}

// signList wraps a body in a Trusted List document and signs it.
//
// The canonicalization here is written independently of the verifier's, so a
// test passes because both agree on the specification rather than because they
// share an implementation.
func signList(body string, signer *SchemeKey, corrupt bool) ([]byte, error) {
	const (
		nsTSL   = "http://uri.etsi.org/02231/v2#"
		nsDSig  = "http://www.w3.org/2000/09/xmldsig#"
		algC14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
		algSig  = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
		algDig  = "http://www.w3.org/2001/04/xmlenc#sha256"
		algEnv  = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	)

	// The signature namespace is declared on the signature element rather than on
	// the document element. Under exclusive canonicalization an element carries
	// only the namespaces it actually uses, so a declaration the document element
	// does not use would be dropped from the canonical form and the raw bytes
	// would stop being their own canonical form, which is what keeps the digest
	// below computable without reimplementing canonicalization here.
	document := fmt.Sprintf(
		`<TrustServiceStatusList xmlns="%s">%s</TrustServiceStatusList>`, nsTSL, body)

	digest := sha256.Sum256([]byte(document))

	signedInfo := fmt.Sprintf(
		`<ds:SignedInfo xmlns:ds="%s"><ds:CanonicalizationMethod Algorithm="%s"></ds:CanonicalizationMethod>`+
			`<ds:SignatureMethod Algorithm="%s"></ds:SignatureMethod>`+
			`<ds:Reference URI=""><ds:Transforms>`+
			`<ds:Transform Algorithm="%s"></ds:Transform>`+
			`<ds:Transform Algorithm="%s"></ds:Transform>`+
			`</ds:Transforms><ds:DigestMethod Algorithm="%s"></ds:DigestMethod>`+
			`<ds:DigestValue>%s</ds:DigestValue></ds:Reference></ds:SignedInfo>`,
		nsDSig, algC14N, algSig, algEnv, algC14N, algDig,
		base64.StdEncoding.EncodeToString(digest[:]))

	signedInfoDigest := sha256.Sum256([]byte(signedInfo))

	signature, err := rsa.SignPKCS1v15(rand.Reader, signer.Key, crypto.SHA256, signedInfoDigest[:])
	if err != nil {
		return nil, err
	}

	if corrupt {
		signature[len(signature)-1] ^= 0xff
	}

	sig := fmt.Sprintf(
		`<ds:Signature xmlns:ds="%s">%s<ds:SignatureValue>%s</ds:SignatureValue>`+
			`<ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate>`+
			`</ds:X509Data></ds:KeyInfo></ds:Signature>`,
		nsDSig, signedInfo,
		base64.StdEncoding.EncodeToString(signature),
		base64.StdEncoding.EncodeToString(signer.Certificate.Raw))

	// The signature is inserted before the closing tag, which is exactly what an
	// enveloped signature is.
	closing := "</TrustServiceStatusList>"
	signed := strings.TrimSuffix(document, closing) + sig + closing

	return []byte(signed), nil
}

func escapeXML(s string) string {
	var b strings.Builder

	for i := range len(s) {
		switch s[i] {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		default:
			b.WriteByte(s[i])
		}
	}

	return b.String()
}

// SnapshotFiles returns the files of a trust snapshot holding the given lists.
//
// The map is suitable for fstest.MapFS, so a test can read a snapshot without
// touching the filesystem.
func SnapshotFiles(lotl []byte, lists map[string][]byte) (map[string][]byte, error) {
	entries := make([]string, 0, len(lists))

	files := map[string][]byte{"lotl.xml": lotl}

	territories := make([]string, 0, len(lists))
	for t := range lists {
		territories = append(territories, t)
	}

	sort.Strings(territories)

	for _, t := range territories {
		path := "lists/" + strings.ToLower(t) + ".xml"
		files[path] = lists[t]

		entries = append(entries, fmt.Sprintf(
			`%q:{"path":%q,"source_url":"https://trusted-list.test/%s.xml","sha256":%q,"size":%d,"territory":%q}`,
			t, path, strings.ToLower(t), digestHex(lists[t]), len(lists[t]), t))
	}

	manifest := fmt.Sprintf(
		`{"format":"sealway-trust-snapshot/1","generated_at":"2026-08-15T00:00:00Z",`+
			`"lotl":{"path":"lotl.xml","source_url":"https://ec.europa.eu/tools/lotl/eu-lotl.xml",`+
			`"sha256":%q,"size":%d},"lists":{%s}}`,
		digestHex(lotl), len(lotl), strings.Join(entries, ","))

	files["manifest.json"] = []byte(manifest)

	return files, nil
}

func digestHex(data []byte) string {
	sum := sha256.Sum256(data)

	const hexDigits = "0123456789abcdef"

	out := make([]byte, 0, len(sum)*2)
	for _, b := range sum {
		out = append(out, hexDigits[b>>4], hexDigits[b&0x0f])
	}

	return string(out)
}

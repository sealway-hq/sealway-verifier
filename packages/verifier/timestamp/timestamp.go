// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

// Package timestamp parses and cryptographically verifies the RFC 3161 token
// embedded in a Sealway certificate.
//
// The token is not merely decoded: its CMS signature is actually verified
// against the signer certificate carried inside it. Three notions are kept
// strictly apart, because conflating them would overclaim:
//
//   - the CMS signature is cryptographically valid;
//   - the signer certificate chains to a trusted root;
//   - the timestamp is a qualified electronic time stamp under eIDAS.
//
// This package establishes the first, exposes the material needed for the
// second, and never asserts the third.
package timestamp

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/digitorus/pkcs7"
)

// DefaultMaxSize bounds the DER artifact accepted by Parse.
const DefaultMaxSize = 4 << 20 // 4 MiB

// Sentinel errors describing a malformed or unusable artifact.
var (
	// ErrMalformed is returned when the artifact is not a well formed RFC 3161
	// response or timestamp token.
	ErrMalformed = errors.New("timestamp: malformed RFC 3161 artifact")
	// ErrNoToken is returned when a response carries no timestamp token.
	ErrNoToken = errors.New("timestamp: the response carries no timestamp token")
	// ErrNoSignerCertificate is returned when the token embeds no certificate
	// for its signer, which makes the signature unverifiable.
	ErrNoSignerCertificate = errors.New("timestamp: the token embeds no signer certificate")
	// ErrAmbiguousSigner is returned when the token does not have exactly one
	// identifiable signer.
	ErrAmbiguousSigner = errors.New("timestamp: the token does not have exactly one identifiable signer")
	// ErrTooLarge is returned when the artifact exceeds the configured limit.
	ErrTooLarge = errors.New("timestamp: artifact exceeds the maximum accepted size")
)

// ResponseStatus is the PKIStatusInfo of a full RFC 3161 response.
type ResponseStatus struct {
	// Status is the numeric PKIStatus value.
	Status int
	// Name is the human readable form of Status.
	Name string
	// Text carries the optional free text explanation of the responder.
	Text []string
}

// Granted reports whether the responder issued a token.
func (s ResponseStatus) Granted() bool {
	return s.Status == statusGranted || s.Status == statusGrantedWithMods
}

// Token is a parsed RFC 3161 timestamp token.
//
// Parsing does not verify anything: call VerifySignature and VerifyImprint to
// establish the cryptographic properties.
type Token struct {
	// ResponseStatus is set when the artifact was a full TimeStampResp rather
	// than a bare TimeStampToken. Both encodings occur in the wild and both are
	// accepted.
	ResponseStatus *ResponseStatus

	// Version is the TSTInfo version, which is 1 for RFC 3161.
	Version int
	// Policy is the dotted OID of the TSA policy under which the token was
	// issued.
	Policy string
	// HashAlgorithm is the algorithm of the message imprint.
	HashAlgorithm crypto.Hash
	// HashAlgorithmName is the human readable name of HashAlgorithm, or the
	// dotted OID when the algorithm is not recognised.
	HashAlgorithmName string
	// MessageImprint is the digest the timestamp covers. For a Sealway proof it
	// is the proof Merkle root.
	MessageImprint []byte
	// SerialNumber is the decimal serial number assigned by the TSA.
	SerialNumber string
	// GenTime is the time asserted by the TSA.
	GenTime time.Time
	// Accuracy is the declared precision of GenTime, or zero when absent.
	Accuracy time.Duration
	// Ordering reports whether the TSA guarantees an ordering of its tokens.
	Ordering bool
	// Nonce is the decimal nonce echoed by the TSA, empty when absent.
	Nonce string

	// Certificates are the certificates carried by the token.
	Certificates []*x509.Certificate
	// Signer is the certificate that signed the token, when it could be
	// identified unambiguously.
	Signer *x509.Certificate

	// HasQualifiedStatement reports whether the token carries the ETSI
	// EN 319 422 statement claiming qualified status. This is a claim made by
	// the issuer, not a verified property: establishing qualification requires
	// validating the signer against the EU trusted list.
	HasQualifiedStatement bool

	// Raw is the DER encoding of the timestamp token itself, without any
	// surrounding response envelope.
	Raw []byte

	p7 *pkcs7.PKCS7
}

// Parse decodes an RFC 3161 artifact.
//
// Both encodings produced in practice are accepted: a full TimeStampResp and a
// bare TimeStampToken, which is a CMS ContentInfo. The two are told apart by
// inspecting the DER structure rather than by trial and error, so a malformed
// artifact cannot be mistaken for the other encoding.
//
// Parse performs no cryptographic verification.
func Parse(der []byte) (*Token, error) {
	if len(der) == 0 {
		return nil, fmt.Errorf("%w: artifact is empty", ErrMalformed)
	}

	if len(der) > DefaultMaxSize {
		return nil, fmt.Errorf("%w: %d bytes", ErrTooLarge, len(der))
	}

	tokenDER, status, err := split(der)
	if err != nil {
		return nil, err
	}

	t, err := parseToken(tokenDER)
	if err != nil {
		return nil, err
	}

	t.ResponseStatus = status

	return t, nil
}

// split separates an artifact into its timestamp token and, when present, the
// response status that wrapped it.
func split(der []byte) (token []byte, status *ResponseStatus, err error) {
	// A CMS ContentInfo starts with an OBJECT IDENTIFIER, a TimeStampResp starts
	// with a SEQUENCE. Attempting the ContentInfo shape first is therefore
	// unambiguous rather than a guess.
	var ci contentInfo
	if rest, cErr := asn1.Unmarshal(der, &ci); cErr == nil && len(rest) == 0 && ci.ContentType.Equal(oidSignedData) {
		return der, nil, nil
	}

	var resp timeStampResp

	rest, rErr := asn1.Unmarshal(der, &resp)
	if rErr != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrMalformed, rErr)
	}

	if len(rest) > 0 {
		return nil, nil, fmt.Errorf("%w: %d trailing bytes after the response", ErrMalformed, len(rest))
	}

	status = &ResponseStatus{
		Status: resp.Status.Status,
		Name:   statusName(resp.Status.Status),
		Text:   resp.Status.StatusString,
	}

	if len(resp.TimeStampToken.FullBytes) == 0 {
		return nil, status, ErrNoToken
	}

	return resp.TimeStampToken.FullBytes, status, nil
}

func parseToken(der []byte) (*Token, error) {
	ct, err := contentType(der)
	if err != nil {
		return nil, err
	}

	if !ct.Equal(oidCTTSTInfo) {
		return nil, fmt.Errorf("%w: encapsulated content type is %s, expected id-ct-TSTInfo (%s)",
			ErrMalformed, ct, oidCTTSTInfo)
	}

	p7, err := pkcs7.Parse(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}

	var info tstInfo

	rest, err := asn1.Unmarshal(p7.Content, &info)
	if err != nil {
		return nil, fmt.Errorf("%w: TSTInfo: %w", ErrMalformed, err)
	}

	if len(rest) > 0 {
		return nil, fmt.Errorf("%w: %d trailing bytes after TSTInfo", ErrMalformed, len(rest))
	}

	if len(info.MessageImprint.HashedMessage) == 0 {
		return nil, fmt.Errorf("%w: TSTInfo carries no message imprint", ErrMalformed)
	}

	hashFunc, hashName := hashFromOID(info.MessageImprint.HashAlgorithm.Algorithm)

	t := &Token{
		Version:               info.Version,
		Policy:                info.Policy.String(),
		HashAlgorithm:         hashFunc,
		HashAlgorithmName:     hashName,
		MessageImprint:        bytes.Clone(info.MessageImprint.HashedMessage),
		SerialNumber:          decimal(info.SerialNumber),
		GenTime:               info.GenTime.UTC(),
		Accuracy:              info.Accuracy.duration(),
		Ordering:              info.Ordering,
		Nonce:                 decimal(info.Nonce),
		Certificates:          p7.Certificates,
		HasQualifiedStatement: hasQualifiedStatement(info, p7.Certificates),
		Raw:                   bytes.Clone(der),
		p7:                    p7,
	}

	t.Signer = p7.GetOnlySigner()

	return t, nil
}

func decimal(n *big.Int) string {
	if n == nil {
		return ""
	}

	return n.String()
}

func hasQualifiedStatement(info tstInfo, certs []*x509.Certificate) bool {
	for _, e := range info.Extensions {
		if e.Id.Equal(oidETSIQualifiedTimestamp) {
			return true
		}
	}

	for _, c := range certs {
		for _, e := range c.Extensions {
			if e.Id.Equal(oidETSIQualifiedTimestamp) {
				return true
			}
		}
	}

	return false
}

// VerifySignature verifies the CMS signature of the token against the signer
// certificate embedded in it.
//
// It establishes that the signed attributes, and through them the TSTInfo
// content, were signed by the holder of the private key matching that
// certificate. It deliberately does not validate the certificate chain: use
// VerifyChain for that, and never present a valid signature as proof that the
// signer is trusted.
func (t *Token) VerifySignature() error {
	if t == nil || t.p7 == nil {
		return ErrMalformed
	}

	if len(t.p7.Certificates) == 0 {
		return ErrNoSignerCertificate
	}

	if t.Signer == nil {
		return ErrAmbiguousSigner
	}

	if err := t.p7.Verify(); err != nil {
		return fmt.Errorf("timestamp: the CMS signature is not valid: %w", err)
	}

	return nil
}

// VerifyChain validates the signer certificate against the supplied trust
// anchors, at the time asserted by the token.
//
// It is only meaningful when the caller supplies a trust store; the verifier
// ships none, because deciding which roots to trust is a policy decision that
// belongs to the caller.
func (t *Token) VerifyChain(roots *x509.CertPool) error {
	if t == nil || t.p7 == nil {
		return ErrMalformed
	}

	if roots == nil {
		return errors.New("timestamp: no trust anchors were supplied")
	}

	intermediates := x509.NewCertPool()
	for _, c := range t.p7.Certificates {
		intermediates.AddCert(c)
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   t.GenTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}

	if err := t.p7.VerifyWithOpts(opts); err != nil {
		return fmt.Errorf("timestamp: the signer certificate is not trusted: %w", err)
	}

	return nil
}

// VerifyImprint reports whether the token covers exactly the supplied digest.
//
// This is the decisive property of a Sealway timestamp: the message imprint must
// equal the proof Merkle root byte for byte.
func (t *Token) VerifyImprint(digest []byte) bool {
	if t == nil || len(digest) == 0 {
		return false
	}

	return bytes.Equal(t.MessageImprint, digest)
}

// SignerSubject returns the distinguished name of the signer certificate.
func (t *Token) SignerSubject() string {
	if t == nil || t.Signer == nil {
		return ""
	}

	return t.Signer.Subject.String()
}

// SignerIssuer returns the distinguished name of the signer certificate issuer.
func (t *Token) SignerIssuer() string {
	if t == nil || t.Signer == nil {
		return ""
	}

	return t.Signer.Issuer.String()
}

// HasTimestampingUsage reports whether the signer certificate carries the
// extended key usage RFC 3161 requires of a timestamping authority.
func (t *Token) HasTimestampingUsage() bool {
	if t == nil || t.Signer == nil {
		return false
	}

	for _, u := range t.Signer.ExtKeyUsage {
		if u == x509.ExtKeyUsageTimeStamping {
			return true
		}
	}

	return false
}

// SignerValidAt reports whether the signer certificate was within its validity
// period at the given time.
func (t *Token) SignerValidAt(at time.Time) bool {
	if t == nil || t.Signer == nil {
		return false
	}

	return !at.Before(t.Signer.NotBefore) && !at.After(t.Signer.NotAfter)
}

// contentType decodes the CMS encapsulated content type of the token.
//
// RFC 3161 requires a timestamp token to encapsulate id-ct-TSTInfo. A token
// declaring anything else is not a timestamp token, whatever its payload
// happens to decode to.
func contentType(der []byte) (asn1.ObjectIdentifier, error) {
	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("%w: ContentInfo: %w", ErrMalformed, err)
	}

	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("%w: CMS content type is %s, expected SignedData (%s)",
			ErrMalformed, ci.ContentType, oidSignedData)
	}

	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("%w: SignedData: %w", ErrMalformed, err)
	}

	return sd.EncapContentInfo.EContentType, nil
}

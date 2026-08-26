// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

// Package prooftest builds synthetic Sealway proofs for tests.
//
// Everything it produces is generated deterministically at test time: a
// throwaway timestamping authority, a real RFC 3161 token, a real certificate
// document and a real bundle archive. Tests therefore exercise the same parsing
// and verification paths as production input, and they can also produce the
// tampered variants a verifier must reject.
//
// It is a test helper and must never be imported by production code.
package prooftest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/digitorus/pkcs7"
)

// Object identifiers used when building a timestamp token.
var (
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidCTTSTInfo  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidSHA512     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidSHA256     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

	// DefaultPolicyOID is the TSA policy asserted by the generated tokens.
	DefaultPolicyOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}
)

// DefaultGenTime is the time asserted by generated tokens. It is fixed so that
// every generated artifact is reproducible.
var DefaultGenTime = time.Date(2026, time.August, 14, 8, 30, 27, 0, time.UTC)

// TSA is a throwaway timestamping authority used to build test tokens.
type TSA struct {
	RootCert *x509.Certificate
	RootKey  *ecdsa.PrivateKey
	RootDER  []byte

	SignerCert *x509.Certificate
	SignerKey  *ecdsa.PrivateKey
	SignerDER  []byte
}

// CRLDistributionPoint and OCSPResponder are where a generated timestamping
// certificate says its revocation status is published. Nothing serves them: they
// exist so that a certificate carries the pointers a real one carries.
const (
	CRLDistributionPoint = "http://crl.example.test/tsa.crl"
	OCSPResponder        = "http://ocsp.example.test"
)

// NewTSA builds a throwaway certificate authority and a timestamping
// certificate issued by it.
func NewTSA() (*TSA, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Sealway Verifier Test TSA Root", Country: []string{"ES"}},
		NotBefore:             DefaultGenTime.Add(-24 * time.Hour),
		NotAfter:              DefaultGenTime.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}

	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, err
	}

	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	signerTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Sealway Verifier Test TSU", Country: []string{"ES"}},
		NotBefore:             DefaultGenTime.Add(-24 * time.Hour),
		NotAfter:              DefaultGenTime.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
		// A real timestamping certificate names where its revocation status is
		// published. Generated ones do too, so that what the verifier reports
		// about revocation is exercised against a realistic certificate.
		CRLDistributionPoints: []string{CRLDistributionPoint},
		OCSPServer:            []string{OCSPResponder},
	}

	signerDER, err := x509.CreateCertificate(rand.Reader, signerTmpl, rootCert, &signerKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}

	signerCert, err := x509.ParseCertificate(signerDER)
	if err != nil {
		return nil, err
	}

	return &TSA{
		RootCert:   rootCert,
		RootKey:    rootKey,
		RootDER:    rootDER,
		SignerCert: signerCert,
		SignerKey:  signerKey,
		SignerDER:  signerDER,
	}, nil
}

// RootPool returns a certificate pool holding the throwaway root.
func (t *TSA) RootPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(t.RootCert)

	return pool
}

// TokenOptions configures a generated timestamp token.
type TokenOptions struct {
	// Imprint is the digest the token covers.
	Imprint []byte
	// HashOID names the algorithm of the imprint. It defaults to SHA-512.
	HashOID asn1.ObjectIdentifier
	// Policy is the asserted TSA policy. It defaults to DefaultPolicyOID.
	Policy asn1.ObjectIdentifier
	// Serial is the asserted serial number. It defaults to 4242.
	Serial *big.Int
	// GenTime is the asserted time. It defaults to DefaultGenTime.
	GenTime time.Time
	// Version overrides the TSTInfo version, for malformed token tests.
	Version int
	// OmitCertificates leaves the signer certificate out of the token.
	OmitCertificates bool
	// WrapInResponse encodes the token inside a full TimeStampResp.
	WrapInResponse bool
	// ResponseStatus is the PKIStatus of the wrapping response.
	ResponseStatus int
	// CorruptSignature flips a bit of the signature after signing.
	CorruptSignature bool
	// SignerCert and SignerKey override the signing identity.
	SignerCert *x509.Certificate
	SignerKey  *ecdsa.PrivateKey
}

type messageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time `asn1:"generalized"`
}

type pkiStatusInfo struct {
	Status int
}

type timeStampResp struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

// Token builds a real RFC 3161 artifact signed by the throwaway authority.
func (t *TSA) Token(opts TokenOptions) ([]byte, error) {
	opts = opts.withDefaults()

	info := tstInfo{
		Version: opts.Version,
		Policy:  opts.Policy,
		MessageImprint: messageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm:  opts.HashOID,
				Parameters: asn1.RawValue{Tag: asn1.TagNull},
			},
			HashedMessage: opts.Imprint,
		},
		SerialNumber: opts.Serial,
		GenTime:      opts.GenTime,
	}

	content, err := asn1.Marshal(info)
	if err != nil {
		return nil, fmt.Errorf("prooftest: cannot encode TSTInfo: %w", err)
	}

	sd, err := pkcs7.NewSignedData(content)
	if err != nil {
		return nil, fmt.Errorf("prooftest: cannot build SignedData: %w", err)
	}

	sd.SetContentType(oidCTTSTInfo)
	sd.SetDigestAlgorithm(oidSHA256)

	signerCert, signerKey := opts.SignerCert, opts.SignerKey
	if signerCert == nil {
		signerCert, signerKey = t.SignerCert, t.SignerKey
	}

	config := pkcs7.SignerInfoConfig{SkipCertificates: opts.OmitCertificates}
	if err = sd.AddSigner(signerCert, signerKey, config); err != nil {
		return nil, fmt.Errorf("prooftest: cannot add the signer: %w", err)
	}

	token, err := sd.Finish()
	if err != nil {
		return nil, fmt.Errorf("prooftest: cannot finish the token: %w", err)
	}

	if opts.CorruptSignature {
		token = corruptSignature(token)
	}

	if !opts.WrapInResponse {
		return token, nil
	}

	resp := timeStampResp{
		Status:         pkiStatusInfo{Status: opts.ResponseStatus},
		TimeStampToken: asn1.RawValue{FullBytes: token},
	}

	if opts.ResponseStatus != 0 && opts.ResponseStatus != 1 {
		resp.TimeStampToken = asn1.RawValue{}
	}

	out, err := asn1.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("prooftest: cannot encode the response: %w", err)
	}

	return out, nil
}

func (o TokenOptions) withDefaults() TokenOptions {
	if len(o.Imprint) == 0 {
		sum := sha512.Sum512(nil)
		o.Imprint = sum[:]
	}

	if o.HashOID == nil {
		o.HashOID = oidSHA512
	}

	if o.Policy == nil {
		o.Policy = DefaultPolicyOID
	}

	if o.Serial == nil {
		o.Serial = big.NewInt(4242)
	}

	if o.GenTime.IsZero() {
		o.GenTime = DefaultGenTime
	}

	if o.Version == 0 {
		o.Version = 1
	}

	return o
}

// corruptSignature flips the last byte of the DER encoding of a token.
//
// The trailing bytes of a SignedData belong to the signature value, so this
// reliably invalidates the signature while leaving the structure parseable.
func corruptSignature(token []byte) []byte {
	out := make([]byte, len(token))
	copy(out, token)

	if len(out) > 0 {
		out[len(out)-1] ^= 0xff
	}

	return out
}

// SignedDataOID returns the CMS SignedData content type identifier.
func SignedDataOID() asn1.ObjectIdentifier { return oidSignedData }

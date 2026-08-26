// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package prooftest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"golang.org/x/crypto/ocsp"
)

// revocationEvidence builds the long term validation attachments a certificate
// carries: the certification path, and a signed statement of the signing
// certificate's revocation status.
//
// The response is signed by the throwaway authority, so a verifier checking it
// against that authority accepts it and a verifier checking it against any other
// does not. That is the property the evidence rests on: it is material a proof
// carries, never something the proof asserts on its own say-so.
func (t *TSA) revocationEvidence(opts RevocationOptions) ([]Attachment, error) {
	tmpl := ocsp.Response{
		Status:           opts.Status,
		SerialNumber:     t.SignerCert.SerialNumber,
		ThisUpdate:       opts.ThisUpdate,
		RevocationReason: opts.Reason,
		RevokedAt:        opts.RevokedAt,
	}

	if tmpl.ThisUpdate.IsZero() {
		// A capture made after a grace period, which is what the evidence is
		// meant to look like.
		tmpl.ThisUpdate = DefaultGenTime.Add(time.Hour)
	}

	if tmpl.Status == ocsp.Revoked && tmpl.RevokedAt.IsZero() {
		tmpl.RevokedAt = DefaultGenTime.Add(-time.Hour)
	}

	tmpl.NextUpdate = tmpl.ThisUpdate.Add(24 * time.Hour)

	responder, key := t.RootCert, crypto.Signer(t.RootKey)

	if opts.DelegatedResponder {
		cert, delegateKey, err := t.delegatedResponder(!opts.OmitOCSPSigningUsage)
		if err != nil {
			return nil, err
		}

		// CreateResponse embeds a responder certificate only when the template
		// carries one; the parameter alone just names the responder.
		tmpl.Certificate = cert
		responder, key = cert, crypto.Signer(delegateKey)
	}

	der, err := ocsp.CreateResponse(t.RootCert, responder, tmpl, key)
	if err != nil {
		return nil, err
	}

	if opts.Corrupt {
		der[len(der)-1] ^= 0xff
	}

	out := []Attachment{{
		Name:        RevocationAttachmentName,
		Description: "Revocation status of the timestamping certificate",
		Content:     der,
	}}

	if !opts.OmitChain {
		out = append(out, Attachment{
			Name:        ChainAttachmentName,
			Description: "Certification path of the timestamping certificate",
			Content:     t.RootDER,
		})
	}

	return out, nil
}

// delegatedResponder issues a certificate for an authority that does not sign
// its own revocation answers.
func (t *TSA) delegatedResponder(withOCSPSigning bool) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "Sealway Verifier Test OCSP Responder", Country: []string{"ES"}},
		NotBefore:    DefaultGenTime.Add(-24 * time.Hour),
		NotAfter:     DefaultGenTime.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	if withOCSPSigning {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, t.RootCert, &key.PublicKey, t.RootKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

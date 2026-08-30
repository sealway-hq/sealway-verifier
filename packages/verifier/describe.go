// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package verifier

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/sealway-hq/sealway-verifier/packages/verifier/proof"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/timestamp"
)

// describeToken renders a parsed token as the facts it states about itself.
func describeToken(t *timestamp.Token) *TimestampDetails {
	out := &TimestampDetails{
		Version:            t.Version,
		Policy:             t.Policy,
		SerialNumber:       t.SerialNumber,
		Ordering:           t.Ordering,
		Nonce:              t.Nonce,
		HashAlgorithm:      t.HashAlgorithmName,
		QualifiedStatement: t.HasQualifiedStatement,
	}

	if !t.GenTime.IsZero() {
		out.GenTime = t.GenTime.UTC().Format(time.RFC3339)
	}

	if t.Accuracy > 0 {
		out.Accuracy = t.Accuracy.String()
	}

	if len(t.MessageImprint) > 0 {
		out.MessageImprint = proof.Hash(t.MessageImprint).String()
	}

	if t.ResponseStatus != nil {
		out.ResponseStatus = fmt.Sprintf("%d (%s)", t.ResponseStatus.Status, t.ResponseStatus.Name)
	}

	for _, c := range t.Certificates {
		out.Certificates = append(out.Certificates, describeCertificate(c))
	}

	if t.Signer != nil {
		d := describeCertificate(t.Signer)
		out.Signer = &d
	}

	return out
}

// describeCertificate names a certificate the way a person reads one.
//
// The fingerprint is SHA-256 because that is what a Trusted List entry and every
// certificate viewer show, so it is the value a reader can compare against
// something else.
func describeCertificate(c *x509.Certificate) CertificateDetails {
	sum := sha256.Sum256(c.Raw)

	d := CertificateDetails{
		CommonName:         c.Subject.CommonName,
		Subject:            c.Subject.String(),
		Issuer:             c.Issuer.String(),
		IssuerCommonName:   c.Issuer.CommonName,
		SerialNumber:       c.SerialNumber.String(),
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: c.PublicKeyAlgorithm.String(),
		NotBefore:          c.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:           c.NotAfter.UTC().Format(time.RFC3339),
		SHA256Fingerprint:  hex.EncodeToString(sum[:]),
		OCSPServers:        c.OCSPServer,
		CRLDistribution:    c.CRLDistributionPoints,
		IssuerURLs:         c.IssuingCertificateURL,
	}

	if len(c.Subject.Country) > 0 {
		d.Country = strings.ToUpper(c.Subject.Country[0])
	}

	if len(c.Subject.Organization) > 0 {
		d.Organization = c.Subject.Organization[0]
	}

	for _, u := range c.ExtKeyUsage {
		d.ExtKeyUsage = append(d.ExtKeyUsage, extKeyUsageName(u))
	}

	return d
}

// extKeyUsageName renders an extended key usage as prose. Timestamping and OCSP
// signing are the two that decide anything here, so they are named rather than
// numbered.
func extKeyUsageName(u x509.ExtKeyUsage) string {
	switch u {
	case x509.ExtKeyUsageAny:
		return "any"
	case x509.ExtKeyUsageServerAuth:
		return "server authentication"
	case x509.ExtKeyUsageClientAuth:
		return "client authentication"
	case x509.ExtKeyUsageCodeSigning:
		return "code signing"
	case x509.ExtKeyUsageEmailProtection:
		return "email protection"
	case x509.ExtKeyUsageTimeStamping:
		return "timestamping"
	case x509.ExtKeyUsageOCSPSigning:
		return "OCSP signing"
	default:
		return fmt.Sprintf("usage %d", int(u))
	}
}

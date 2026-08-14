// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

// Package bootstrap carries the anchor that starts the European chain of trust.
//
// Validating a Trusted List does not remove the need for a trust anchor, it
// moves it: the European List of Trusted Lists pins the certificates allowed to
// sign each national list, and the list of lists is itself signed by the
// European Commission. That one certificate has to come from somewhere, and it
// is the only thing this verifier asks a caller to take on faith.
//
// It is shipped as readable material rather than compiled-in opaque bytes so
// that anyone auditing this repository can compare it with the publication in
// the Official Journal of the European Union, and it can be replaced entirely by
// a caller who would rather supply their own.
package bootstrap

import (
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
)

// LOTLLocation is where the European List of Trusted Lists is published.
const LOTLLocation = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"

//go:embed eu-lotl-signer.pem
var lotlSignerPEM []byte

// LOTLSignerFingerprints are the SHA-256 fingerprints of the certificates
// accepted as signers of the list of lists.
//
// They are stated here so that a reader can check the shipped material without
// parsing it, and so that a test can fail loudly if the file is ever replaced by
// something else.
//
// Confirm them against the Official Journal before relying on them. The set is
// append-only: a certificate is added when the Commission rotates, and an old
// one is never removed, because a list issued under it must stay verifiable.
var LOTLSignerFingerprints = []string{
	"e0a620fbb6747362bb933ac44169d676a553444716cf5f31605f12a22b8396b1",
}

// ErrUnexpectedMaterial is returned when the shipped anchor does not match the
// fingerprints declared above.
var ErrUnexpectedMaterial = errors.New("bootstrap: the shipped trust anchor does not match its declared fingerprint")

// LOTLSigners returns the certificates accepted as signers of the list of lists.
//
// The material is checked against the declared fingerprints on every call, so a
// silent substitution in the repository cannot go unnoticed.
func LOTLSigners() ([]*x509.Certificate, error) {
	certs, err := parsePEM(lotlSignerPEM)
	if err != nil {
		return nil, err
	}

	allowed := make(map[string]bool, len(LOTLSignerFingerprints))
	for _, f := range LOTLSignerFingerprints {
		allowed[f] = true
	}

	for _, c := range certs {
		sum := sha256.Sum256(c.Raw)
		if !allowed[hex.EncodeToString(sum[:])] {
			return nil, fmt.Errorf("%w: %s has fingerprint %x",
				ErrUnexpectedMaterial, c.Subject.CommonName, sum)
		}
	}

	if len(certs) != len(LOTLSignerFingerprints) {
		return nil, fmt.Errorf("%w: %d certificates for %d declared fingerprints",
			ErrUnexpectedMaterial, len(certs), len(LOTLSignerFingerprints))
	}

	return certs, nil
}

func parsePEM(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate

	rest := data

	for {
		var block *pem.Block

		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: cannot parse the shipped anchor: %w", err)
		}

		out = append(out, cert)
	}

	if len(out) == 0 {
		return nil, errors.New("bootstrap: no certificate in the shipped anchor")
	}

	return out, nil
}

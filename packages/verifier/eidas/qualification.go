// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

// Package eidas determines whether an RFC 3161 timestamp was produced by a
// qualified trust service, as recorded by the European Trusted Lists.
//
// Qualified status is a legal property, not a cryptographic one. A valid
// signature says who produced a token; only an authenticated Trusted List says
// whether that producer was recognised as qualified, and only for the instant
// the token asserts. The statement inside a token claiming qualified status is
// a claim by its issuer and is never sufficient.
//
// The package is pure computation over data it is handed: it reaches no
// network, touches no filesystem and holds no global state, so the same
// determination runs from a command line tool, a desktop application and a
// browser build.
package eidas

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/sealway-hq/sealway-verifier/packages/verifier/trustlist"
)

// Determination is the outcome of a qualification assessment.
type Determination string

const (
	// Qualified means a certification path was established to a trust service
	// that a Trusted List recorded as qualified at the asserted time.
	Qualified Determination = "qualified"
	// NotQualified means the applicable service existed but was not recognised
	// as qualified at the asserted time.
	NotQualified Determination = "not_qualified"
	// Indeterminate means the question could not be answered: no authenticated
	// list covered the signer, or the material needed was missing or stale.
	//
	// It is never a synonym for failure. An absence of evidence is reported as
	// such rather than turned into a denial.
	Indeterminate Determination = "indeterminate"
)

// String implements fmt.Stringer.
func (d Determination) String() string { return string(d) }

// MatchKind records how a service was found applicable to the signer.
type MatchKind string

const (
	// MatchSigner means a Trusted List identifies the service by the signing
	// certificate itself.
	MatchSigner MatchKind = "signer"
	// MatchIssuer means a Trusted List identifies the service by an authority,
	// and the signing certificate has a valid certification path to it.
	MatchIssuer MatchKind = "issuer"
)

// ServiceMatch is one trust service found applicable to the signer.
type ServiceMatch struct {
	// Territory is the scheme territory of the list that carried the service.
	Territory string
	// ProviderName is the trust service provider.
	ProviderName string
	// ServiceName is the service as published.
	ServiceName string
	// ServiceType is the service type identifier.
	ServiceType string
	// Status is the status in effect at the asserted time.
	Status string
	// StatusSince is when that status took effect.
	StatusSince time.Time
	// Kind records whether the list identified the signer directly or through
	// an authority.
	Kind MatchKind
	// IdentitySubject names the certificate the list published as the identity.
	IdentitySubject string
	// Qualified reports whether Status means the service was recognised.
	Qualified bool
	// PathLength is the number of certificates between the signer and the
	// identity, zero for a direct match.
	PathLength int
}

// Result is the outcome of a qualification assessment.
type Result struct {
	// Determination answers the question.
	Determination Determination
	// Matches are every applicable service found, qualified or not. They are
	// reported in full so that a disagreement between entries is visible rather
	// than resolved silently.
	Matches []ServiceMatch
	// Decisive is the match the determination rests on, when there is one.
	Decisive *ServiceMatch
	// Reasons explain the determination in the order they were established.
	Reasons []string
	// TrustListTerritory is the national list consulted.
	TrustListTerritory string
	// TrustListSequence is the sequence number of that list.
	TrustListSequence uint64
	// TrustListIssued is when that list was issued.
	TrustListIssued time.Time
}

// Conflicting reports whether the applicable services disagree, meaning at least
// one recognised the service and another did not.
//
// It happens legitimately when a provider restructures its entries, for example
// moving from identifying a signing unit to identifying the authority that
// issues its certificates. A caller should surface it rather than hide it.
func (r *Result) Conflicting() bool {
	var qualified, notQualified bool

	for _, m := range r.Matches {
		if m.Qualified {
			qualified = true
		} else {
			notQualified = true
		}
	}

	return qualified && notQualified
}

// Request is what a determination needs.
type Request struct {
	// Signer is the certificate that signed the timestamp token.
	Signer *x509.Certificate
	// Intermediates are certificates that may complete a path between the
	// signer and a Trusted List identity: the ones the token carried, plus any
	// the caller obtained separately.
	Intermediates []*x509.Certificate
	// GenTime is the instant the token asserts. Every temporal question is
	// answered at this instant, never at the moment of verification: a service
	// recognised then does not stop having been recognised because its
	// recognition ended later.
	GenTime time.Time
	// List is the authenticated national Trusted List to consult.
	List *trustlist.List
}

// Assess determines whether the signer of a timestamp was a qualified trust
// service at the asserted time.
//
// A determination of Qualified requires all of the following: an authenticated
// list covering the signer, a service of a qualified timestamping type, a
// certification path from the signer to one of that service's published
// identities valid at the asserted time, and a status recorded as recognised at
// that same instant. Anything less is Indeterminate or NotQualified, never
// Qualified.
func Assess(req Request) *Result {
	res := &Result{Determination: Indeterminate}

	if req.Signer == nil {
		res.Reasons = append(res.Reasons, "the timestamp carries no identifiable signer certificate")

		return res
	}

	if req.List == nil {
		res.Reasons = append(res.Reasons,
			"no authenticated Trusted List was available for the signer")

		return res
	}

	res.TrustListTerritory = req.List.Territory
	res.TrustListSequence = req.List.SequenceNumber
	res.TrustListIssued = req.List.IssueDate

	if req.GenTime.IsZero() {
		res.Reasons = append(res.Reasons, "the timestamp asserts no time to evaluate the status at")

		return res
	}

	res.Matches = applicableServices(req)

	if len(res.Matches) == 0 {
		res.Reasons = append(res.Reasons, fmt.Sprintf(
			"no qualified timestamping service of the %s Trusted List covers the signing certificate %q",
			req.List.Territory, req.Signer.Subject.CommonName))

		return res
	}

	decisive := decisiveMatch(res.Matches)
	res.Decisive = &decisive

	if decisive.Qualified {
		res.Determination = Qualified
		res.Reasons = append(res.Reasons, fmt.Sprintf(
			"the signing certificate has a certification path to %q, published by %s in the %s "+
				"Trusted List as a %s service recorded as %s since %s",
			decisive.IdentitySubject, decisive.ProviderName, decisive.Territory,
			shortIdentifier(decisive.ServiceType), shortIdentifier(decisive.Status),
			decisive.StatusSince.Format(time.RFC3339)))
	} else {
		res.Determination = NotQualified
		res.Reasons = append(res.Reasons, fmt.Sprintf(
			"the applicable service %q of %s was recorded as %s at the asserted time",
			decisive.ServiceName, decisive.ProviderName, shortIdentifier(decisive.Status)))
	}

	if res.Conflicting() {
		res.Reasons = append(res.Reasons,
			"the Trusted List carries several entries covering this certificate and they do not "+
				"agree; every one of them is reported so the disagreement stays visible")
	}

	return res
}

// applicableServices finds every qualified timestamping service the signer can
// be attributed to.
//
// Matching is on the certification path, never on the signing certificate
// alone. A list normally identifies a service by the authority that issues its
// certificates, so looking only for the signing certificate would miss the
// entry that actually covers it, and would answer the wrong question when a
// provider restructures its entries.
func applicableServices(req Request) []ServiceMatch {
	var out []ServiceMatch

	intermediates := x509.NewCertPool()

	for _, c := range req.Intermediates {
		if c != nil && !c.Equal(req.Signer) {
			intermediates.AddCert(c)
		}
	}

	for _, provider := range req.List.Providers {
		for _, service := range provider.Services {
			if !trustlist.TimestampService(service.Type) {
				continue
			}

			status, since, known := service.StatusAt(req.GenTime)
			if !known {
				continue
			}

			for _, identity := range service.IdentitiesAt(req.GenTime) {
				if identity.Certificate == nil {
					continue
				}

				kind, length, ok := attribute(req, identity.Certificate, intermediates)
				if !ok {
					continue
				}

				out = append(out, ServiceMatch{
					Territory:       req.List.Territory,
					ProviderName:    provider.Name,
					ServiceName:     service.Name,
					ServiceType:     service.Type,
					Status:          status,
					StatusSince:     since,
					Kind:            kind,
					IdentitySubject: identity.Certificate.Subject.CommonName,
					Qualified:       trustlist.Qualified(status),
					PathLength:      length,
				})

				break // one match per service is enough
			}
		}
	}

	return out
}

// attribute reports whether the signer can be attributed to a published
// identity, and how.
func attribute(
	req Request,
	identity *x509.Certificate,
	intermediates *x509.CertPool,
) (kind MatchKind, pathLength int, ok bool) {
	if identity.Equal(req.Signer) {
		return MatchSigner, 0, true
	}

	roots := x509.NewCertPool()
	roots.AddCert(identity)

	// The path is validated at the asserted time, so a certificate that has
	// since expired does not retroactively stop having been valid. Key usage is
	// not constrained here: the timestamping usage of the signing certificate is
	// checked separately, and an authority is not expected to carry it.
	chains, err := req.Signer.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   req.GenTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil || len(chains) == 0 {
		return "", 0, false
	}

	shortest := len(chains[0])
	for _, c := range chains {
		if len(c) < shortest {
			shortest = len(c)
		}
	}

	return MatchIssuer, shortest - 1, true
}

// decisiveMatch picks the match a determination rests on.
//
// The condition a Trusted List answers is existential: it asks whether a
// certification path exists to a service recognised as qualified. A recognised
// service therefore decides the outcome even when another entry covering the
// same certificate is not recognised, because withdrawing one entry retracts
// that entry's claim rather than negating a different entry that still covers
// the certificate. The disagreement is reported separately so it stays visible.
//
// Among equally recognised matches the most specific one wins: a list that names
// the signing certificate itself is a more direct statement than one that names
// an authority above it.
func decisiveMatch(matches []ServiceMatch) ServiceMatch {
	best := matches[0]

	for _, m := range matches[1:] {
		switch {
		case m.Qualified != best.Qualified:
			if m.Qualified {
				best = m
			}
		case m.PathLength < best.PathLength:
			best = m
		}
	}

	return best
}

// shortIdentifier trims a URI identifier down to its last component, which is
// what a reader recognises.
func shortIdentifier(id string) string {
	if i := strings.LastIndexAny(id, "#/"); i >= 0 && i+1 < len(id) {
		return id[i+1:]
	}

	return id
}

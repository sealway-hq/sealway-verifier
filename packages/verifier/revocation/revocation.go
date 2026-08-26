// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

// Package revocation decides whether a certificate was usable at a given
// instant, from revocation evidence supplied alongside it.
//
// # Why the evidence travels with the proof
//
// Revocation status is not reconstructible after the fact. A responder answers
// about now, not about a moment in the past, and an old certificate eventually
// falls out of the lists that once covered it. Evidence captured near the time
// a signature was made is the only thing that keeps the question answerable
// later, which is why a proof carries it rather than the verifier fetching it.
//
// # What a revocation means depends on when it happened
//
// A certificate revoked after a timestamp was made does not retroactively
// invalidate it: the key was still recognised when it signed. The exception is a
// revocation for compromise, where the compromise may well predate the
// revocation and nothing in the evidence says when it began. That case is
// reported as undecided rather than as failure, because claiming the timestamp
// is broken would assert something the evidence does not establish.
package revocation

import (
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"

	"golang.org/x/crypto/ocsp"
)

// Status is what the evidence establishes about a certificate at an instant.
type Status string

const (
	// StatusGood means the certificate was not revoked at the asserted time.
	StatusGood Status = "good"
	// StatusRevoked means the certificate had been revoked by then.
	StatusRevoked Status = "revoked"
	// StatusRevokedLater means the certificate was revoked, but only after the
	// asserted time, for a reason that does not reach back before it.
	StatusRevokedLater Status = "revoked_later"
	// StatusUndetermined means the evidence did not settle the question.
	StatusUndetermined Status = "undetermined"
)

// Sentinel errors a caller must distinguish.
var (
	// ErrNoEvidence is returned when nothing covering the certificate was
	// supplied. It is an absence, never a finding.
	ErrNoEvidence = errors.New("revocation: no evidence covers the certificate")
	// ErrMalformed is returned when evidence could not be read or its signature
	// did not verify against the issuer.
	ErrMalformed = errors.New("revocation: the evidence is not usable")
	// ErrUntrustedResponder is returned when a delegated responder is not
	// authorised to answer for the issuer.
	ErrUntrustedResponder = errors.New("revocation: the responder is not authorised by the issuer")
	// ErrStale is returned when the evidence predates the instant asked about,
	// and so cannot answer it.
	ErrStale = errors.New("revocation: the evidence predates the asserted time")
)

// Result is what one piece of evidence established.
type Result struct {
	// Status is the conclusion.
	Status Status
	// ThisUpdate is the instant the responder's answer is current as of.
	ThisUpdate time.Time
	// NextUpdate is when a newer answer is expected, when the responder said.
	NextUpdate time.Time
	// ProducedAt is when the response was signed.
	ProducedAt time.Time
	// Freshness is how long after the asserted time the answer was current.
	// It is never negative: evidence that predates the question is refused.
	Freshness time.Duration
	// RevokedAt is when the revocation took effect, for a revoked certificate.
	RevokedAt time.Time
	// Reason is the RFC 5280 reason code of a revocation.
	Reason int
	// ReasonName is that code in words.
	ReasonName string
	// Delegated reports whether a responder other than the issuer answered.
	Delegated bool
	// Responder names whoever signed the answer.
	Responder string
}

// Check reports what the supplied evidence establishes about cert at the given
// instant.
//
// Every response is verified against issuer before anything it says is read, so
// evidence a proof carries is material and never authority. Responses covering
// other certificates are ignored rather than refused: a proof may carry evidence
// for a whole certification path.
//
// The instant is the time a signature asserts, not the time of verification.
// Evidence that predates it cannot answer it and is refused with ErrStale, which
// is what stops an older and more convenient answer being substituted for the
// one that covers the question.
func Check(responses [][]byte, cert, issuer *x509.Certificate, at time.Time) (*Result, error) {
	if cert == nil || issuer == nil {
		return nil, fmt.Errorf("%w: a certificate and its issuer are required", ErrMalformed)
	}

	if len(responses) == 0 {
		return nil, ErrNoEvidence
	}

	var (
		covered bool
		errs    []error
	)

	for _, der := range responses {
		resp, err := ocsp.ParseResponseForCert(der, cert, issuer)
		if err != nil {
			// A response about a different certificate is not a fault: a proof
			// may carry evidence for a whole path. Re-reading it without asking
			// for a particular certificate separates that case from evidence
			// that is genuinely unusable, without matching on error text.
			if _, other := ocsp.ParseResponseForCert(der, nil, issuer); other == nil {
				continue
			}

			errs = append(errs, fmt.Errorf("%w: %w", ErrMalformed, err))

			continue
		}

		covered = true

		if err := authorised(resp, issuer); err != nil {
			errs = append(errs, err)

			continue
		}

		if resp.ThisUpdate.Before(at) {
			errs = append(errs, fmt.Errorf("%w: current as of %s, which is before %s",
				ErrStale, resp.ThisUpdate.Format(time.RFC3339), at.Format(time.RFC3339)))

			continue
		}

		return conclude(resp, issuer, at), nil
	}

	if !covered && len(errs) == 0 {
		return nil, ErrNoEvidence
	}

	return nil, errors.Join(errs...)
}

// authorised checks that whoever signed the response was entitled to.
//
// The signature itself is already verified against the issuer. What remains is
// the authorisation of a delegated responder: RFC 6960 section 4.2.2.2 requires
// that a certificate other than the issuer's own carry the OCSP signing extended
// key usage. Without that check any certificate the same authority ever issued
// would be able to answer for it, which is a far larger set than the one
// certificate the authority meant to delegate to.
func authorised(resp *ocsp.Response, issuer *x509.Certificate) error {
	if resp.Certificate == nil {
		return nil // the issuer answered for itself
	}

	if slices.Contains(resp.Certificate.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning) {
		return nil
	}

	return fmt.Errorf("%w: %q was delegated by %q but does not carry the OCSP signing usage",
		ErrUntrustedResponder, resp.Certificate.Subject.CommonName, issuer.Subject.CommonName)
}

// conclude turns a verified response into what it establishes at the instant
// asked about.
func conclude(resp *ocsp.Response, issuer *x509.Certificate, at time.Time) *Result {
	out := &Result{
		ThisUpdate: resp.ThisUpdate,
		NextUpdate: resp.NextUpdate,
		ProducedAt: resp.ProducedAt,
		Freshness:  resp.ThisUpdate.Sub(at),
		Responder:  issuer.Subject.CommonName,
	}

	if resp.Certificate != nil {
		out.Delegated = true
		out.Responder = resp.Certificate.Subject.CommonName
	}

	switch resp.Status {
	case ocsp.Good:
		out.Status = StatusGood

		return out

	case ocsp.Revoked:
		out.RevokedAt = resp.RevokedAt
		out.Reason = resp.RevocationReason
		out.ReasonName = reasonName(resp.RevocationReason)

		switch {
		case !resp.RevokedAt.After(at):
			// Already revoked when the signature was made.
			out.Status = StatusRevoked
		case compromise(resp.RevocationReason):
			// The revocation came later, but a compromise has no start date in
			// the evidence and may well predate the signature. Nothing here
			// settles it either way.
			out.Status = StatusUndetermined
		default:
			out.Status = StatusRevokedLater
		}

		return out

	default:
		out.Status = StatusUndetermined

		return out
	}
}

// compromise reports whether a reason code means the private key may have been
// in someone else's hands before the revocation was recorded.
func compromise(reason int) bool {
	switch reason {
	case ocsp.KeyCompromise, ocsp.CACompromise, ocsp.AACompromise:
		return true
	default:
		return false
	}
}

// reasonName renders an RFC 5280 reason code as prose, because a report is read
// by people.
func reasonName(reason int) string {
	switch reason {
	case ocsp.Unspecified:
		return "unspecified"
	case ocsp.KeyCompromise:
		return "key compromise"
	case ocsp.CACompromise:
		return "certification authority compromise"
	case 3:
		return "affiliation changed"
	case ocsp.Superseded:
		return "superseded"
	case ocsp.CessationOfOperation:
		return "cessation of operation"
	case ocsp.CertificateHold:
		return "certificate hold"
	case 8:
		return "removed from the revocation list"
	case ocsp.PrivilegeWithdrawn:
		return "privilege withdrawn"
	case ocsp.AACompromise:
		return "attribute authority compromise"
	default:
		return fmt.Sprintf("reason code %d", reason)
	}
}

// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package eidas

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sealway-hq/sealway-verifier/packages/verifier/trust"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/trust/bootstrap"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/trustlist"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/trustlist/xmldsig"
)

// Evaluator turns raw trust material into a qualification determination.
//
// It performs the authentication chain in order: the list of lists is verified
// against the bootstrap anchor, the national list against the certificates the
// list of lists pins for its territory, and only then is the national list read.
// Nothing is read before it has been authenticated, so a mirror or a cache can
// never introduce a service.
type Evaluator struct {
	provider trust.Provider
	signers  []*x509.Certificate
	limits   xmldsig.Limits
}

// EvaluatorOption configures an Evaluator.
type EvaluatorOption func(*Evaluator)

// WithSigners overrides the certificates accepted as signers of the list of
// lists.
func WithSigners(certs []*x509.Certificate) EvaluatorOption {
	return func(e *Evaluator) {
		if len(certs) > 0 {
			e.signers = certs
		}
	}
}

// WithLimits bounds the documents the evaluator will parse.
func WithLimits(l xmldsig.Limits) EvaluatorOption {
	return func(e *Evaluator) { e.limits = l }
}

// NewEvaluator returns an evaluator reading material from a provider.
func NewEvaluator(p trust.Provider, opts ...EvaluatorOption) (*Evaluator, error) {
	signers, err := bootstrap.LOTLSigners()
	if err != nil {
		return nil, err
	}

	e := &Evaluator{provider: p, signers: signers}

	for _, o := range opts {
		if o != nil {
			o(e)
		}
	}

	if e.provider == nil {
		return nil, errors.New("eidas: no trust material provider was supplied")
	}

	return e, nil
}

// Assessment is a determination together with what it was based on.
type Assessment struct {
	*Result

	// TrustSource describes where the material came from.
	TrustSource string
	// LOTLSequence is the sequence number of the list of lists used.
	LOTLSequence uint64
	// Stale reports whether a list was read after its operator undertook to
	// publish a new one. It does not invalidate anything; it is a reason to be
	// careful about how current the answer is.
	Stale bool
}

// Evaluate determines the qualified status of a timestamp signer.
//
// validationTime is the instant to answer at, which is the time the token
// asserts. The material itself is fetched for that territory only, and a failure
// to obtain or authenticate it yields Indeterminate: an answer that cannot be
// established is not an answer in the negative.
func (e *Evaluator) Evaluate(
	ctx context.Context,
	signer *x509.Certificate,
	intermediates []*x509.Certificate,
	validationTime time.Time,
	offline bool,
) *Assessment {
	out := &Assessment{Result: &Result{Determination: Indeterminate}}

	if signer == nil {
		out.Reasons = append(out.Reasons, "the timestamp carries no identifiable signer certificate")

		return out
	}

	territory := territoryOf(signer)
	if territory == "" {
		out.Reasons = append(out.Reasons, fmt.Sprintf(
			"the signing certificate %q declares no country, so the national Trusted List that "+
				"would cover it cannot be identified", signer.Subject.CommonName))

		return out
	}

	material, err := e.provider.Material(ctx, trust.Request{
		ValidationTime: validationTime,
		Territory:      territory,
		Offline:        offline,
	})
	if err != nil {
		out.TrustSource = e.provider.Describe()
		out.Reasons = append(out.Reasons, fmt.Sprintf(
			"no authenticated Trusted List material could be obtained for %s: %s", territory, err))

		return out
	}

	out.TrustSource = material.Source

	lotl, err := e.authenticateLOTL(material)
	if err != nil {
		out.Reasons = append(out.Reasons, err.Error())

		return out
	}

	out.LOTLSequence = lotl.SequenceNumber

	if lotl.Stale(validationTime) {
		out.Stale = true
	}

	list, err := e.authenticateList(lotl, material, territory)
	if err != nil {
		out.Reasons = append(out.Reasons, err.Error())

		return out
	}

	if list.Stale(validationTime) {
		out.Stale = true
	}

	all := append([]*x509.Certificate{}, intermediates...)
	all = append(all, material.Certificates...)

	out.Result = Assess(Request{
		Signer:        signer,
		Intermediates: all,
		GenTime:       validationTime,
		List:          list,
	})

	return out
}

// authenticateLOTL verifies the list of lists against the bootstrap anchor.
func (e *Evaluator) authenticateLOTL(m *trust.Material) (*trustlist.List, error) {
	if len(m.LOTL) == 0 {
		return nil, errors.New("the trust material carries no European List of Trusted Lists")
	}

	verified, err := xmldsig.Verify(m.LOTL, e.signers, e.limits)
	if err != nil {
		return nil, fmt.Errorf("the European List of Trusted Lists is not authentic: %w", err)
	}

	lotl, err := trustlist.Parse(verified)
	if err != nil {
		return nil, fmt.Errorf("the European List of Trusted Lists is unusable: %w", err)
	}

	if !lotl.IsListOfLists() {
		return nil, errors.New("the document published as the list of lists is not one")
	}

	return lotl, nil
}

// authenticateList verifies a national list against the certificates the list of
// lists pins for its territory.
func (e *Evaluator) authenticateList(
	lotl *trustlist.List,
	m *trust.Material,
	territory string,
) (*trustlist.List, error) {
	raw, ok := m.Lists[strings.ToUpper(territory)]
	if !ok || len(raw) == 0 {
		return nil, fmt.Errorf("the trust material carries no Trusted List for %s", territory)
	}

	pointer, ok := lotl.PointerFor(territory)
	if !ok {
		return nil, fmt.Errorf(
			"the European List of Trusted Lists carries no machine readable pointer for %s", territory)
	}

	if len(pointer.SigningCertificates) == 0 {
		return nil, fmt.Errorf(
			"the European List of Trusted Lists pins no signing certificate for %s, so its list "+
				"cannot be authenticated", territory)
	}

	verified, err := xmldsig.Verify(raw, pointer.SigningCertificates, e.limits)
	if err != nil {
		return nil, fmt.Errorf("the %s Trusted List is not authentic: %w", territory, err)
	}

	list, err := trustlist.Parse(verified)
	if err != nil {
		return nil, fmt.Errorf("the %s Trusted List is unusable: %w", territory, err)
	}

	if !strings.EqualFold(list.Territory, territory) {
		return nil, fmt.Errorf(
			"the list published for %s declares the territory %s", territory, list.Territory)
	}

	return list, nil
}

// territoryOf returns the scheme territory whose Trusted List would cover a
// certificate.
//
// A trust service is supervised by the member state it is established in, which
// its certificate states as the subject country.
func territoryOf(cert *x509.Certificate) string {
	for _, c := range cert.Subject.Country {
		if c = strings.ToUpper(strings.TrimSpace(c)); c != "" {
			return c
		}
	}

	for _, c := range cert.Issuer.Country {
		if c = strings.ToUpper(strings.TrimSpace(c)); c != "" {
			return c
		}
	}

	return ""
}

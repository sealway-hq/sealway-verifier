// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package verifier

import (
	"context"
	"fmt"

	"github.com/sealway-hq/sealway-verifier/packages/verifier/eidas"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/proof"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/report"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/timestamp"
)

// TimestampInput is a bare RFC 3161 artifact and whatever a caller knows about
// it.
//
// Everything but the token is optional, and each omission narrows what can be
// established rather than turning into a failure.
type TimestampInput struct {
	// Token is the DER encoded artifact, either a full TimeStampResp or a bare
	// TimeStampToken.
	Token []byte
	// Imprint is the digest the caller expects the token to stamp. Without it
	// the imprint is read and reported but compared with nothing: a token on its
	// own says what it covers, and whether that is the right thing is a question
	// only the caller can ask.
	Imprint []byte
	// Chain is a certification path in concatenated DER, when the caller has one
	// separately from the token.
	Chain []byte
	// Revocation holds signed revocation responses covering the signing
	// certificate. A proof carries these inside its certificate; a caller
	// verifying a token on its own supplies them here or leaves revocation
	// unestablished.
	Revocation [][]byte
}

// VerifyTimestamp verifies a bare RFC 3161 timestamp on its own.
//
// It answers a narrower question than verifying a proof: what this token
// establishes, and whether the authority that issued it was a qualified trust
// service at the time it says. Nothing about a proof, its files or its anchors
// is involved, because none of that is present.
//
// The report carries only the timestamp section. Every check in it is performed
// by the same code that runs inside a full verification, so a token that
// verifies here verifies identically inside the proof that carries it.
func (v *Verifier) VerifyTimestamp(ctx context.Context, in TimestampInput) (*Report, error) {
	if len(in.Token) == 0 {
		return nil, fmt.Errorf("%w: a timestamp artifact is required", ErrInvalidInput)
	}

	r := newRun(v.opts, nil)
	r.evidence = evidence{chain: in.Chain, revocation: in.Revocation}
	r.imprint = proof.Hash(in.Imprint)

	token, err := timestamp.Parse(in.Token)
	if err != nil {
		r.builder.Add(report.SectionTimestamp, sectionTimestampTitle,
			report.NewInvalid("timestamp.structure", "RFC 3161 token structure",
				"The timestamp artifact could not be parsed: "+err.Error()))
		r.skipTimestampChecks("The timestamp token could not be parsed.")

		// An artifact that will not parse is a verdict about that artifact, not a
		// failure of this tool: the caller gets a report saying the structure is
		// invalid rather than an error they must interpret.
		//nolint:nilerr // reporting the outcome is the contract, not returning err
		return r.builder.Build(), nil
	}

	r.token = token

	r.checkTokenStructure(token)
	r.checkTokenSignature(token)
	r.checkSignerUsage(token)
	r.checkTokenImprint(token)
	r.checkTokenMetadata(token)
	r.checkTrustChain(ctx, token)

	return r.builder.Build(), nil
}

// TimestampDetails is what a token says about itself, decoded and no more.
//
// It carries no verdict. Reading a token and believing it are different acts,
// and a caller that wants the second calls VerifyTimestamp.
type TimestampDetails struct {
	// Version, Policy, SerialNumber and GenTime are the token's own fields.
	Version      int    `json:"version"`
	Policy       string `json:"policy_oid,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	GenTime      string `json:"gen_time,omitempty"`
	// Accuracy is the uncertainty the authority declares, if any.
	Accuracy string `json:"accuracy,omitempty"`
	Ordering bool   `json:"ordering"`
	Nonce    string `json:"nonce,omitempty"`
	// MessageImprint is what the token stamps, and the algorithm it stamps with.
	MessageImprint string `json:"message_imprint,omitempty"`
	HashAlgorithm  string `json:"hash_algorithm,omitempty"`
	// ResponseStatus is present when the artifact is a full TimeStampResp.
	ResponseStatus string `json:"response_status,omitempty"`
	// QualifiedStatement reports whether the token carries the ETSI statement
	// claiming qualified status. It is a claim by its issuer and never evidence.
	QualifiedStatement bool `json:"qualified_statement"`
	// Signer identifies the certificate that signed the token.
	Signer *CertificateDetails `json:"signer,omitempty"`
	// Certificates lists everything the token embeds, the signer included.
	Certificates []CertificateDetails `json:"certificates,omitempty"`
}

// CertificateDetails names a certificate the way a person reads one.
type CertificateDetails struct {
	CommonName         string   `json:"common_name,omitempty"`
	Subject            string   `json:"subject,omitempty"`
	Issuer             string   `json:"issuer,omitempty"`
	IssuerCommonName   string   `json:"issuer_common_name,omitempty"`
	SerialNumber       string   `json:"serial_number,omitempty"`
	SignatureAlgorithm string   `json:"signature_algorithm,omitempty"`
	PublicKeyAlgorithm string   `json:"public_key_algorithm,omitempty"`
	NotBefore          string   `json:"not_before,omitempty"`
	NotAfter           string   `json:"not_after,omitempty"`
	Country            string   `json:"country,omitempty"`
	Organization       string   `json:"organization,omitempty"`
	SHA256Fingerprint  string   `json:"sha256_fingerprint,omitempty"`
	ExtKeyUsage        []string `json:"extended_key_usage,omitempty"`
	OCSPServers        []string `json:"ocsp_servers,omitempty"`
	CRLDistribution    []string `json:"crl_distribution_points,omitempty"`
	IssuerURLs         []string `json:"issuer_urls,omitempty"`
}

// InspectTimestamp decodes a timestamp artifact without judging it.
//
// A malformed artifact is an error. A well formed one that says something
// unwelcome is not: that is what VerifyTimestamp is for.
func InspectTimestamp(der []byte) (*TimestampDetails, error) {
	if len(der) == 0 {
		return nil, fmt.Errorf("%w: a timestamp artifact is required", ErrInvalidInput)
	}

	t, err := timestamp.Parse(der)
	if err != nil {
		return nil, err
	}

	return describeToken(t), nil
}

// RequiredTerritory reports the scheme territory whose Trusted List would cover
// the authority that signed a timestamp.
//
// A caller serving Trusted List material can use it to fetch the one list a
// proof needs instead of every list the European Union publishes, which is
// twenty-five megabytes to answer a question about one of them.
//
// It returns an empty string when the certificate names no country, which is
// the same reason qualified status would be left undetermined.
func RequiredTerritory(der []byte) (string, error) {
	t, err := timestamp.Parse(der)
	if err != nil {
		return "", err
	}

	if t.Signer == nil {
		return "", fmt.Errorf("%w: the token carries no identifiable signer certificate",
			ErrInvalidInput)
	}

	return eidas.TerritoryOf(t.Signer), nil
}

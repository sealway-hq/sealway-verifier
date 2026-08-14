// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package verifier

import (
	"context"
	"crypto"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/sealway-hq/sealway-verifier/packages/verifier/eidas"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/pdf"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/proof"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/report"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/timestamp"
)

const sectionTimestampTitle = "Qualified timestamp"

// verifyTimestamp parses the embedded RFC 3161 artifact, verifies its CMS
// signature and checks that it covers the proof Merkle root.
//
// The decisive property is the last one: the message imprint must equal the
// proof Merkle root byte for byte. A signature that verifies proves who issued
// the token, not what the token covers.
func (r *run) verifyTimestamp(ctx context.Context, cert *pdf.Certificate) {
	reportProgress(r.opts.progress, Progress{Stage: StageTimestamp})

	if len(cert.Timestamp) == 0 {
		r.skipTimestampStage("The certificate does not embed an RFC 3161 timestamp artifact.")

		return
	}

	token, err := timestamp.Parse(cert.Timestamp)
	if err != nil {
		r.builder.Add(report.SectionTimestamp, sectionTimestampTitle,
			report.NewInvalid("timestamp.structure", "RFC 3161 token structure",
				"The embedded timestamp artifact could not be parsed: "+err.Error()))
		r.skipTimestampChecks("The timestamp token could not be parsed.")

		return
	}

	r.token = token

	r.checkTokenStructure(token)
	r.checkTokenSignature(token)
	r.checkSignerUsage(token)
	r.checkTokenImprint(token)
	r.checkTokenMetadata(token)
	r.checkTrustChain(ctx, token)
}

func (r *run) skipTimestampStage(reason string) {
	r.builder.Add(report.SectionTimestamp, sectionTimestampTitle,
		report.NewSkipped("timestamp.structure", "RFC 3161 token structure", reason))
	r.skipTimestampChecks(reason)
}

// skipTimestampChecks records every remaining timestamp step as skipped.
//
// The whole stage is emitted even when the token could not be read, so that the
// shape of the report does not depend on the outcome and a consumer always finds
// the same identifiers.
func (r *run) skipTimestampChecks(reason string) {
	r.builder.Add(report.SectionTimestamp, sectionTimestampTitle,
		report.NewSkipped("timestamp.signature", "CMS signature", reason),
		report.NewSkipped("timestamp.signer_usage", "Timestamping certificate usage", reason),
		report.NewSkipped("timestamp.imprint", "Message imprint matches the proof root", reason),
		report.NewSkipped("timestamp.metadata", "Declared timestamp metadata", reason),
		report.NewIndeterminate("timestamp.trust_chain", "Signer certificate path", reason),
		report.NewIndeterminate("timestamp.qualified", "Qualified electronic timestamp", reason))
}

func (r *run) checkTokenStructure(t *timestamp.Token) {
	const (
		id    = "timestamp.structure"
		title = "RFC 3161 token structure"
	)

	details := map[string]string{
		"policy_oid":     t.Policy,
		"serial_number":  t.SerialNumber,
		"gen_time":       t.GenTime.Format(time.RFC3339),
		"hash_algorithm": t.HashAlgorithmName,
	}

	if t.ResponseStatus != nil {
		details["response_status"] = fmt.Sprintf("%d (%s)", t.ResponseStatus.Status, t.ResponseStatus.Name)

		if !t.ResponseStatus.Granted() {
			r.builder.Add(report.SectionTimestamp, sectionTimestampTitle,
				report.NewInvalid(id, title, fmt.Sprintf(
					"The timestamping authority did not grant a token: status %d (%s). %s",
					t.ResponseStatus.Status, t.ResponseStatus.Name,
					strings.Join(t.ResponseStatus.Text, " "))).
					WithDetails(details))

			return
		}
	}

	if t.Version != 1 {
		r.builder.Add(report.SectionTimestamp, sectionTimestampTitle,
			report.NewInvalid(id, title, fmt.Sprintf(
				"The token declares TSTInfo version %d, but RFC 3161 defines version 1.", t.Version)).
				WithDetails(details))

		return
	}

	kind := "a bare timestamp token"
	if t.ResponseStatus != nil {
		kind = "a full timestamp response"
	}

	r.builder.Add(report.SectionTimestamp, sectionTimestampTitle,
		report.NewValid(id, title, fmt.Sprintf(
			"The embedded artifact is %s and was parsed as a well formed RFC 3161 structure.", kind)).
			WithDetails(details))
}

func (r *run) checkTokenSignature(t *timestamp.Token) {
	const (
		id    = "timestamp.signature"
		title = "CMS signature"
	)

	if len(t.Certificates) == 0 {
		r.builder.Add(report.SectionTimestamp, sectionTimestampTitle,
			report.NewSkipped(id, title,
				"The token embeds no signer certificate, so its CMS signature cannot be verified."))

		return
	}

	if err := t.VerifySignature(); err != nil {
		r.builder.Add(report.SectionTimestamp, sectionTimestampTitle,
			report.NewInvalid(id, title, "The CMS signature of the token is not valid: "+err.Error()))

		return
	}

	r.builder.Add(report.SectionTimestamp, sectionTimestampTitle,
		report.NewValid(id, title,
			"The CMS signature of the token is cryptographically valid for the signer certificate "+
				"embedded in it. This proves the token was issued by the holder of that key; it says "+
				"nothing about whether that signer is trusted.").
			WithDetails(map[string]string{
				"signer_subject": t.SignerSubject(),
				"signer_issuer":  t.SignerIssuer(),
			}))
}

func (r *run) checkSignerUsage(t *timestamp.Token) {
	const (
		id    = "timestamp.signer_usage"
		title = "Timestamping certificate usage"
	)

	if t.Signer == nil {
		r.builder.Add(report.SectionTimestamp, sectionTimestampTitle,
			report.NewSkipped(id, title,
				"The signer certificate could not be identified unambiguously, so its usage could not "+
					"be checked."))

		return
	}

	if !t.HasTimestampingUsage() {
		r.builder.Add(report.SectionTimestamp, sectionTimestampTitle,
			report.NewInvalid(id, title,
				"The signer certificate does not carry the timeStamping extended key usage that "+
					"RFC 3161 requires of a timestamping authority."))

		return
	}

	if !t.SignerValidAt(t.GenTime) {
		r.builder.Add(report.SectionTimestamp, sectionTimestampTitle,
			report.NewInvalid(id, title, fmt.Sprintf(
				"The signer certificate was not within its validity period at the asserted time %s "+
					"(valid from %s to %s).",
				t.GenTime.Format(time.RFC3339),
				t.Signer.NotBefore.UTC().Format(time.RFC3339),
				t.Signer.NotAfter.UTC().Format(time.RFC3339))))

		return
	}

	r.builder.Add(report.SectionTimestamp, sectionTimestampTitle,
		report.NewValid(id, title,
			"The signer certificate carries the timeStamping extended key usage and was within its "+
				"validity period at the time asserted by the token.").
			WithDetails(map[string]string{
				"not_before": t.Signer.NotBefore.UTC().Format(time.RFC3339),
				"not_after":  t.Signer.NotAfter.UTC().Format(time.RFC3339),
			}))
}

func (r *run) checkTokenImprint(t *timestamp.Token) {
	const (
		id    = "timestamp.imprint"
		title = "Message imprint matches the proof root"
	)

	root := r.manifest.Proof.MerkleRoot
	if root.IsZero() {
		r.builder.Add(report.SectionTimestamp, sectionTimestampTitle,
			report.NewSkipped(id, title,
				"The manifest declares no proof Merkle root, so there is nothing to compare the "+
					"message imprint with."))

		return
	}

	details := map[string]string{
		"hash_algorithm":  t.HashAlgorithmName,
		"message_imprint": proof.Hash(t.MessageImprint).String(),
		"proof_root":      root.String(),
	}

	if t.HashAlgorithm != crypto.SHA512 {
		r.builder.Add(report.SectionTimestamp, sectionTimestampTitle,
			report.NewInvalid(id, title, fmt.Sprintf(
				"The message imprint uses %s, but a Sealway proof root is a SHA-512 digest.",
				t.HashAlgorithmName)).
				WithDetails(details))

		return
	}

	if !t.VerifyImprint(root.Bytes()) {
		r.builder.Add(report.SectionTimestamp, sectionTimestampTitle,
			report.NewInvalid(id, title,
				"The message imprint of the timestamp does not equal the certified proof Merkle root. "+
					"The timestamp does not cover this proof.").
				WithDetails(details))

		return
	}

	r.builder.Add(report.SectionTimestamp, sectionTimestampTitle,
		report.NewValid(id, title, fmt.Sprintf(
			"The message imprint equals the certified proof Merkle root byte for byte. Subject to "+
				"trusting the timestamping authority, the proof root existed at %s.",
			t.GenTime.Format(time.RFC3339))).
			WithDetails(details))
}

// checkTokenMetadata compares the timestamp metadata recorded in the manifest
// with the token itself.
//
// The token is authoritative. The manifest copy exists for readability, and a
// disagreement is worth reporting because it means the two describe different
// things.
func (r *run) checkTokenMetadata(t *timestamp.Token) {
	const (
		id    = "timestamp.metadata"
		title = "Declared timestamp metadata"
	)

	declared := r.manifest.Notarization.ProofTimestamp
	if declared == nil {
		r.builder.Add(report.SectionTimestamp, sectionTimestampTitle,
			report.NewOutOfScope(id, title,
				"The manifest records no timestamp metadata, so there is nothing to compare with the "+
					"token. The token itself is the authoritative source."))

		return
	}

	var problems []string

	if declared.SerialNumber != "" && declared.SerialNumber != t.SerialNumber {
		problems = append(problems, fmt.Sprintf("the manifest declares serial number %s, the token carries %s",
			declared.SerialNumber, t.SerialNumber))
	}

	if declared.PolicyOID != "" && declared.PolicyOID != t.Policy {
		problems = append(problems, fmt.Sprintf("the manifest declares policy %s, the token carries %s",
			declared.PolicyOID, t.Policy))
	}

	if !declared.TimestampedAt.IsZero() && !declared.TimestampedAt.UTC().Equal(t.GenTime) {
		problems = append(problems, fmt.Sprintf("the manifest declares the time %s, the token asserts %s",
			declared.TimestampedAt.UTC().Format(time.RFC3339), t.GenTime.Format(time.RFC3339)))
	}

	if len(problems) > 0 {
		r.builder.Add(report.SectionTimestamp, sectionTimestampTitle,
			report.NewInvalid(id, title,
				"The timestamp metadata recorded in the manifest contradicts the token: "+
					strings.Join(problems, "; ")+"."))

		return
	}

	r.builder.Add(report.SectionTimestamp, sectionTimestampTitle,
		report.NewValid(id, title,
			"The timestamp metadata recorded in the manifest agrees with the token.").
			WithDetails(map[string]string{
				"tsa_provider": declared.TSAProviderName,
				"policy_oid":   t.Policy,
				"serial":       t.SerialNumber,
				"gen_time":     t.GenTime.Format(time.RFC3339),
			}))
}

// checkTrustChain establishes the certificate chain and the qualified status of
// the timestamp.
//
// A valid CMS signature, a trusted certificate chain and qualified eIDAS status
// are three different things and stay three different checks. The first says who
// produced the token; the second that the producer chains to something the
// caller accepts; only the third, established against an authenticated European
// Trusted List, says the producer was a recognised qualified service at the time
// the token asserts.
func (r *run) checkTrustChain(ctx context.Context, t *timestamp.Token) {
	assessment := r.assessQualification(ctx, t)

	r.checkSignerPath(t, assessment)
	r.checkQualifiedStatus(t, assessment)
}

// assessQualification consults the Trusted Lists, when the caller configured a
// source for them.
func (r *run) assessQualification(ctx context.Context, t *timestamp.Token) *eidas.Assessment {
	if r.opts.trustProvider == nil || t.Signer == nil {
		return nil
	}

	evaluator, err := eidas.NewEvaluator(r.opts.trustProvider,
		eidas.WithLimits(r.opts.limits.TrustList),
		eidas.WithSigners(r.opts.trustListSigners))
	if err != nil {
		return &eidas.Assessment{Result: &eidas.Result{
			Determination: eidas.Indeterminate,
			Reasons:       []string{"the trust material could not be prepared: " + err.Error()},
		}}
	}

	lookupCtx, cancel := context.WithTimeout(ctx, r.opts.networkTimeout)
	defer cancel()

	return evaluator.Evaluate(lookupCtx, t.Signer, t.Certificates, t.GenTime, r.opts.offline)
}

// checkSignerPath reports whether the signing certificate chains to something
// the caller accepts.
//
// A Trusted List is the stronger answer, because the path it establishes ends at
// an authority a member state publishes rather than at a root somebody chose to
// install. Explicit trust anchors remain available for a caller who wants to
// pin their own.
func (r *run) checkSignerPath(t *timestamp.Token, a *eidas.Assessment) {
	const (
		id    = "timestamp.trust_chain"
		title = "Signer certificate path"
	)

	if a != nil && a.Decisive != nil {
		d := a.Decisive

		r.builder.Add(report.SectionTimestamp, sectionTimestampTitle,
			report.NewValid(id, title, fmt.Sprintf(
				"The signing certificate has a valid certification path to %q, which the %s Trusted "+
					"List publishes as the identity of a trust service. The path was validated at %s, "+
					"the time the token asserts.",
				d.IdentitySubject, d.Territory, t.GenTime.Format(time.RFC3339))).
				WithDetails(map[string]string{
					"trust_list":      d.Territory,
					"identity":        d.IdentitySubject,
					"matched_by":      string(d.Kind),
					"path_length":     strconv.Itoa(d.PathLength),
					"trust_source":    a.TrustSource,
					"validation_time": t.GenTime.Format(time.RFC3339),
				}))

		return
	}

	if err := r.trustChainError(t); r.opts.timestampRoots != nil {
		if err != nil {
			r.builder.Add(report.SectionTimestamp, sectionTimestampTitle,
				report.NewInvalid(id, title,
					"The signer certificate does not chain to the supplied trust anchors: "+err.Error()))

			return
		}

		r.builder.Add(report.SectionTimestamp, sectionTimestampTitle,
			report.NewValid(id, title,
				"The signer certificate chains to the supplied trust anchors and was valid at the "+
					"time asserted by the token."))

		return
	}

	reason := "No trust anchors were supplied and no Trusted List source was configured, so the " +
		"signer certificate path was not established."
	if a != nil && len(a.Reasons) > 0 {
		reason = "The signer certificate path could not be established: " + a.Reasons[0]
	}

	r.builder.Add(report.SectionTimestamp, sectionTimestampTitle,
		report.NewIndeterminate(id, title, reason))
}

// checkQualifiedStatus reports whether the timestamp is a qualified electronic
// time stamp.
//
// The statement a token may carry claiming qualified status is never sufficient:
// it is written by the issuer. Only an authenticated Trusted List can answer,
// and only for the instant the token asserts.
func (r *run) checkQualifiedStatus(t *timestamp.Token, a *eidas.Assessment) {
	const (
		id    = "timestamp.qualified"
		title = "Qualified electronic timestamp"
	)

	if a == nil {
		reason := "No Trusted List source was configured, so no claim is made about qualified eIDAS " +
			"status."
		if t.HasQualifiedStatement {
			reason = "The token carries the ETSI EN 319 422 statement claiming qualified status, but " +
				"that is a claim made by its issuer. No Trusted List source was configured, so the " +
				"claim was not checked and no claim is made about qualified eIDAS status."
		}

		r.builder.Add(report.SectionTimestamp, sectionTimestampTitle,
			report.NewIndeterminate(id, title, reason))

		return
	}

	details := map[string]string{
		"determination":   string(a.Determination),
		"validation_time": t.GenTime.Format(time.RFC3339),
		"trust_source":    a.TrustSource,
	}

	if a.TrustListTerritory != "" {
		details["trust_list"] = a.TrustListTerritory
		details["trust_list_sequence"] = strconv.FormatUint(a.TrustListSequence, 10)
	}

	if d := a.Decisive; d != nil {
		details["provider"] = d.ProviderName
		details["service"] = d.ServiceName
		details["service_type"] = shortID(d.ServiceType)
		details["service_status"] = shortID(d.Status)
		details["status_since"] = d.StatusSince.Format(time.RFC3339)
	}

	if a.Conflicting() {
		details["conflicting_entries"] = conflictSummary(a)
	}

	switch a.Determination {
	case eidas.Qualified:
		r.builder.Add(report.SectionTimestamp, sectionTimestampTitle,
			report.NewValid(id, title, qualifiedMessage(a, t)).WithDetails(details))
	case eidas.NotQualified:
		r.builder.Add(report.SectionTimestamp, sectionTimestampTitle,
			report.NewInvalid(id, title, strings.Join(a.Reasons, " ")).WithDetails(details))
	default:
		r.builder.Add(report.SectionTimestamp, sectionTimestampTitle,
			report.NewIndeterminate(id, title,
				"The qualified eIDAS status of this timestamp could not be established. "+
					strings.Join(a.Reasons, " ")).
				WithDetails(details))
	}
}

func qualifiedMessage(a *eidas.Assessment, t *timestamp.Token) string {
	d := a.Decisive

	msg := fmt.Sprintf(
		"At %s, the time this token asserts, %s operated %q as a %s service recorded as %s in the %s "+
			"Trusted List. This timestamp is therefore a qualified electronic time stamp.",
		t.GenTime.Format(time.RFC3339), d.ProviderName, d.ServiceName,
		shortID(d.ServiceType), shortID(d.Status), d.Territory)

	if a.Stale {
		msg += " Note: the Trusted List consulted is past the date its operator undertook to publish " +
			"a new one, so it may not reflect the most recent changes."
	}

	if a.Conflicting() {
		msg += " Note: the Trusted List carries several entries covering this certificate and they " +
			"do not agree; all of them are reported below."
	}

	return msg
}

func conflictSummary(a *eidas.Assessment) string {
	parts := make([]string, 0, len(a.Matches))
	for _, m := range a.Matches {
		parts = append(parts, fmt.Sprintf("%s (%s) = %s",
			m.IdentitySubject, m.Kind, shortID(m.Status)))
	}

	return strings.Join(parts, "; ")
}

func shortID(id string) string {
	if i := strings.LastIndexAny(id, "#/"); i >= 0 && i+1 < len(id) {
		return id[i+1:]
	}

	return id
}

// trustChainError validates the signer chain when trust anchors were supplied.
func (r *run) trustChainError(t *timestamp.Token) error {
	if r.opts.timestampRoots == nil {
		return nil
	}

	return t.VerifyChain(r.opts.timestampRoots)
}

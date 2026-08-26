// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package verifier

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/sealway-hq/sealway-verifier/packages/verifier/bundle"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/pdf"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/proof"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/report"
)

const sectionCertificateTitle = "Certificate"

// readCertificate opens the certificate and extracts the authoritative machine
// readable artifacts from it.
//
// A document that cannot be read at all is an operational failure. A readable
// document missing one of its artifacts is not: it is a certificate that fails
// verification, and the caller still receives a report saying exactly which
// artifact is absent.
func (r *run) readCertificate(rs io.ReadSeeker) (*pdf.Certificate, error) {
	reportProgress(r.opts.progress, Progress{Stage: StageCertificate})

	cert, err := pdf.Open(rs, r.opts.limits.PDF)
	if cert == nil {
		return nil, err
	}

	r.builder.Add(report.SectionCertificate, sectionCertificateTitle,
		report.NewValid("certificate.container", "Certificate document",
			fmt.Sprintf("The certificate was parsed successfully (PDF %s, %d embedded file(s)).",
				cert.PDFVersion, len(cert.Attachments))).
			WithDetail("embedded_files", cert.AttachmentSummary()))

	r.checkManifestAttachment(cert, err)
	r.checkTimestampAttachment(cert, err)
	r.checkSignature(cert)
	r.checkLooseCopies(cert)

	return cert, nil
}

func (r *run) checkManifestAttachment(cert *pdf.Certificate, openErr error) {
	const (
		id    = "certificate.manifest"
		title = "Embedded proof manifest"
	)

	if len(cert.Manifest) == 0 {
		r.builder.Add(report.SectionCertificate, sectionCertificateTitle,
			report.NewInvalid(id, title, fmt.Sprintf(
				"The certificate does not embed %s. A Sealway certificate carries its proof manifest "+
					"as an embedded file; the loose copies a bundle may carry are never used instead. "+
					"Embedded files found: %s.",
				pdf.ManifestAttachmentName, cert.AttachmentSummary())))

		if openErr != nil && !errors.Is(openErr, pdf.ErrManifestNotFound) &&
			!errors.Is(openErr, pdf.ErrTimestampNotFound) {
			r.builder.Add(report.SectionCertificate, sectionCertificateTitle,
				report.NewInvalid("certificate.manifest_extraction", "Manifest extraction",
					openErr.Error()))
		}

		return
	}

	m, err := proof.ParseBytes(cert.Manifest)
	if err != nil {
		r.builder.Add(report.SectionCertificate, sectionCertificateTitle,
			report.NewInvalid(id, title,
				"The embedded proof manifest could not be parsed: "+err.Error()))

		return
	}

	r.builder.Add(report.SectionCertificate, sectionCertificateTitle,
		report.NewValid(id, title, fmt.Sprintf(
			"The embedded proof manifest was extracted and parsed (%d bytes, schema version %s).",
			len(cert.Manifest), m.Version)))

	r.checkManifestSchema(m)
}

func (r *run) checkManifestSchema(m *proof.Manifest) {
	const (
		id    = "certificate.manifest_schema"
		title = "Proof manifest structure"
	)

	if err := m.Validate(); err != nil {
		check := report.NewInvalid(id, title, "The proof manifest is not structurally valid: "+err.Error())

		var verr *proof.ValidationError
		if errors.As(err, &verr) {
			for i, issue := range verr.Issues {
				check = check.WithDetail("issue."+strconv.Itoa(i), issue.String())
			}
		}

		r.builder.Add(report.SectionCertificate, sectionCertificateTitle, check)

		// The manifest is kept even when invalid so that the remaining stages can
		// still report as much diagnostic information as they safely can.
		r.manifest = m
		r.setCertificateMetadata(m)

		return
	}

	r.builder.Add(report.SectionCertificate, sectionCertificateTitle,
		report.NewValid(id, title, fmt.Sprintf(
			"The proof manifest is structurally valid: %d certified item(s), SHA-512 digests, "+
				"unique contiguous positions and well formed inclusion paths.", len(m.Items))))

	r.manifest = m
	r.setCertificateMetadata(m)
}

func (r *run) setCertificateMetadata(m *proof.Manifest) {
	c := &report.Certificate{
		PublicID:        m.Proof.PublicID,
		SchemaVersion:   m.Version,
		Title:           m.Proof.Title,
		Category:        m.Proof.Category,
		HashAlgorithm:   m.Proof.HashAlgorithm,
		ItemCount:       len(m.Items),
		TotalSizeBytes:  m.Proof.TotalSizeBytes,
		MerkleRoot:      m.Proof.MerkleRoot.String(),
		AccumulatorRoot: m.Notarization.AccumulatorRoot.String(),
	}

	if !m.Proof.CreatedAt.IsZero() {
		t := m.Proof.CreatedAt.UTC()
		c.CreatedAt = &t
	}

	if !m.Proof.TimestampedAt.IsZero() {
		t := m.Proof.TimestampedAt.UTC()
		c.TimestampedAt = &t
	}

	r.builder.SetCertificate(c)
}

func (r *run) checkTimestampAttachment(cert *pdf.Certificate, openErr error) {
	const (
		id    = "certificate.timestamp_token"
		title = "Embedded RFC 3161 token"
	)

	if len(cert.Timestamp) == 0 {
		r.builder.Add(report.SectionCertificate, sectionCertificateTitle,
			report.NewInvalid(id, title, fmt.Sprintf(
				"The certificate does not embed %s. Embedded files found: %s.",
				pdf.TimestampAttachmentName, cert.AttachmentSummary())))

		return
	}

	_ = openErr

	r.builder.Add(report.SectionCertificate, sectionCertificateTitle,
		report.NewValid(id, title, fmt.Sprintf(
			"The embedded RFC 3161 artifact was extracted (%d bytes).", len(cert.Timestamp))))
}

func (r *run) checkSignature(cert *pdf.Certificate) {
	const (
		id    = "certificate.signature"
		title = "Certificate digital signature"
	)

	if !cert.Signed {
		r.builder.Add(report.SectionCertificate, sectionCertificateTitle,
			report.NewOutOfScope(id, title,
				"This certificate carries no digital signature, so there is no signature to check. "+
					"The proof does not depend on one: its integrity rests on the embedded manifest, "+
					"the RFC 3161 timestamp and the blockchain anchors, each verified independently "+
					"and none of which a document signature would strengthen."))

		return
	}

	r.builder.Add(report.SectionCertificate, sectionCertificateTitle,
		report.NewOutOfScope(id, title,
			"The certificate carries a digital signature. Verifying document signatures is not "+
				"implemented in this version of the verifier, so the signature was not checked."))
}

// checkLooseCopies compares the convenience copies a bundle carries with the
// authoritative artifacts embedded in the certificate.
//
// The loose copies are never an input to the cryptographic verification. The
// comparison exists because a copy that contradicts the certificate is a
// meaningful integrity signal about the bundle, while a copy that merely differs
// in a non cryptographic field, such as its generation timestamp, is expected.
func (r *run) checkLooseCopies(cert *pdf.Certificate) {
	const (
		id    = "certificate.loose_copies"
		title = "Bundle convenience copies"
	)

	if r.bundle == nil {
		return
	}

	manifestEntry, hasManifest := r.bundle.LooseCopy(bundle.LooseManifestName)
	tokenEntry, hasToken := r.bundle.LooseCopy(bundle.LooseTimestampName)

	if !hasManifest && !hasToken {
		r.builder.Add(report.SectionCertificate, sectionCertificateTitle,
			report.NewOutOfScope(id, title,
				"The bundle carries no loose copy of the proof manifest or of the timestamp token. "+
					"They are optional: the authoritative artifacts are the ones embedded in the "+
					"certificate."))

		return
	}

	var problems, notes []string

	if hasManifest {
		problems, notes = appendManifestComparison(manifestEntry, cert.Manifest, problems, notes)
	}

	if hasToken {
		if data, err := tokenEntry.Bytes(); err != nil {
			problems = append(problems, "the loose timestamp copy could not be read: "+err.Error())
		} else if !bytes.Equal(data, cert.Timestamp) {
			problems = append(problems,
				"the loose timestamp copy is not identical to the embedded RFC 3161 token")
		}
	}

	switch {
	case len(problems) > 0:
		r.builder.Add(report.SectionCertificate, sectionCertificateTitle,
			report.NewInvalid(id, title,
				"The convenience copies carried by the bundle contradict the authoritative artifacts "+
					"embedded in the certificate: "+strings.Join(problems, "; ")+
					". The verification result above is computed from the embedded artifacts only."))
	case len(notes) > 0:
		r.builder.Add(report.SectionCertificate, sectionCertificateTitle,
			report.NewValid(id, title,
				"The convenience copies carried by the bundle agree with the authoritative artifacts "+
					"embedded in the certificate. Non cryptographic differences: "+
					strings.Join(notes, "; ")+"."))
	default:
		r.builder.Add(report.SectionCertificate, sectionCertificateTitle,
			report.NewValid(id, title,
				"The convenience copies carried by the bundle are identical to the authoritative "+
					"artifacts embedded in the certificate."))
	}
}

// appendManifestComparison compares a loose manifest copy with the embedded one,
// separating cryptographic contradictions from harmless differences.
func appendManifestComparison(
	entry bundle.Entry,
	embedded []byte,
	problems, notes []string,
) (outProblems, outNotes []string) {
	data, err := entry.Bytes()
	if err != nil {
		return append(problems, "the loose manifest copy could not be read: "+err.Error()), notes
	}

	if bytes.Equal(data, embedded) {
		return problems, notes
	}

	loose, err := proof.ParseBytes(data)
	if err != nil {
		return append(problems, "the loose manifest copy is not valid JSON: "+err.Error()), notes
	}

	authoritative, err := proof.ParseBytes(embedded)
	if err != nil {
		return problems, notes // the embedded manifest is reported separately
	}

	problems = append(problems, cryptographicDifferences(authoritative, loose)...)

	if len(problems) == 0 {
		notes = append(notes, "the loose manifest copy differs from the embedded one outside of its "+
			"cryptographic fields")
	}

	return problems, notes
}

// cryptographicDifferences lists the disagreements that actually matter between
// two manifests.
func cryptographicDifferences(authoritative, other *proof.Manifest) []string {
	var out []string

	if authoritative.Proof.PublicID != other.Proof.PublicID {
		out = append(out, "the public identifier differs")
	}

	if !authoritative.Proof.MerkleRoot.Equal(other.Proof.MerkleRoot) {
		out = append(out, "the proof Merkle root differs")
	}

	if !authoritative.Notarization.AccumulatorRoot.Equal(other.Notarization.AccumulatorRoot) {
		out = append(out, "the accumulator Merkle root differs")
	}

	a, b := authoritative.ItemsByPosition(), other.ItemsByPosition()
	if len(a) != len(b) {
		return append(out, "the number of certified items differs")
	}

	for i := range a {
		if !a[i].LeafHash.Equal(b[i].LeafHash) {
			out = append(out, fmt.Sprintf("the certified leaf of item %d differs", a[i].Position))
		}
	}

	return out
}

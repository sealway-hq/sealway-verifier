// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

// Package pdf extracts the machine readable artifacts embedded in a Sealway
// certificate.
//
// The certificate is a PDF/A-3b document. Its visible pages are for humans; the
// verifier only ever consumes the embedded attachments, which are the
// authoritative machine readable evidence. Attachments are read, never executed,
// and nothing outside the two expected artifacts is extracted.
//
// Parsing is pure Go with no cgo, no external binary and no shell out.
package pdf

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"

	"github.com/sealway-hq/sealway-verifier/internal/pdfconfig"
)

// Names of the embedded artifacts a Sealway certificate is expected to carry.
const (
	// ManifestAttachmentName is the embedded machine readable proof manifest.
	ManifestAttachmentName = "sealway-proof.json"
	// TimestampAttachmentName is the embedded DER encoded RFC 3161 artifact.
	TimestampAttachmentName = "proof-timestamp.tsr"
)

// Sentinel errors describing a certificate whose structure is unusable.
//
// A missing artifact is not an operational failure: the caller turns it into a
// failing verification step, because a certificate without its machine readable
// evidence is not a valid certificate.
var (
	// ErrManifestNotFound is returned when the proof manifest is not embedded.
	ErrManifestNotFound = errors.New("pdf: the certificate does not embed " + ManifestAttachmentName)
	// ErrTimestampNotFound is returned when the timestamp token is not embedded.
	ErrTimestampNotFound = errors.New("pdf: the certificate does not embed " + TimestampAttachmentName)
	// ErrAmbiguousAttachment is returned when several attachments claim the same
	// expected name, which makes the authoritative artifact undecidable.
	ErrAmbiguousAttachment = errors.New("pdf: several embedded files claim the same name")
	// ErrAttachmentTooLarge is returned when an embedded artifact exceeds the
	// configured limit.
	ErrAttachmentTooLarge = errors.New("pdf: embedded file exceeds the configured size limit")
	// ErrTooManyAttachments is returned when a certificate carries an
	// implausible number of embedded files.
	ErrTooManyAttachments = errors.New("pdf: too many embedded files")
)

// Default resource limits applied to an untrusted certificate.
const (
	DefaultMaxAttachmentSize      = 32 << 20 // 32 MiB per embedded artifact
	DefaultMaxTotalAttachmentSize = 64 << 20 // 64 MiB for all extracted artifacts
	DefaultMaxAttachments         = 64
)

// Limits bounds the resources a hostile certificate can consume.
//
// A zero value selects the defaults.
type Limits struct {
	MaxAttachmentSize      int64
	MaxTotalAttachmentSize int64
	MaxAttachments         int
}

func (l Limits) withDefaults() Limits {
	if l.MaxAttachmentSize <= 0 {
		l.MaxAttachmentSize = DefaultMaxAttachmentSize
	}

	if l.MaxTotalAttachmentSize <= 0 {
		l.MaxTotalAttachmentSize = DefaultMaxTotalAttachmentSize
	}

	if l.MaxAttachments <= 0 {
		l.MaxAttachments = DefaultMaxAttachments
	}

	return l
}

// AttachmentInfo describes one embedded file found in the certificate.
type AttachmentInfo struct {
	// Name is the file name declared by the embedded file specification.
	Name string
	// Description is the optional human readable description.
	Description string
}

// Certificate is the machine readable content of a Sealway certificate.
type Certificate struct {
	// Manifest is the raw sealway-proof.json document.
	Manifest []byte
	// Timestamp is the raw DER RFC 3161 artifact, either a full TimeStampResp or
	// a bare TimeStampToken.
	Timestamp []byte
	// Attachments lists every embedded file found, sorted by name. It is
	// diagnostic information only.
	Attachments []AttachmentInfo
	// Signed reports whether the document carries a digital signature.
	Signed bool
	// PDFVersion is the version declared by the document.
	PDFVersion string
}

// Open reads a Sealway certificate and extracts its embedded artifacts.
//
// The reader is only required to support reading and seeking, so a certificate
// held in memory, read from a file or taken out of a bundle are all handled the
// same way. Nothing is written to disk.
//
// A malformed document produces an error. A well formed document that is
// missing an expected artifact produces a Certificate with the corresponding
// field left nil together with ErrManifestNotFound or ErrTimestampNotFound, so
// the caller can still report everything else it managed to read.
func Open(rs io.ReadSeeker, limits Limits) (cert *Certificate, err error) {
	if rs == nil {
		return nil, errors.New("pdf: no certificate reader was supplied")
	}

	limits = limits.withDefaults()

	// pdfcpu walks deeply nested structures that a hostile document controls.
	// Any panic escaping it is converted into an ordinary error so that a
	// malformed certificate can never take the process down.
	defer func() {
		if r := recover(); r != nil {
			cert = nil
			err = fmt.Errorf("pdf: cannot read the certificate: %v", r)
		}
	}()

	ctx, err := api.ReadValidateAndOptimize(rs, newConfiguration())
	if err != nil {
		return nil, fmt.Errorf("pdf: cannot read the certificate: %w", err)
	}

	stubs, err := ctx.ListAttachments()
	if err != nil {
		return nil, fmt.Errorf("pdf: cannot list the embedded files: %w", err)
	}

	if len(stubs) > limits.MaxAttachments {
		return nil, fmt.Errorf("%w: %d embedded files, the maximum is %d",
			ErrTooManyAttachments, len(stubs), limits.MaxAttachments)
	}

	cert = &Certificate{
		Attachments: attachmentInfos(stubs),
		Signed:      isSigned(ctx),
		PDFVersion:  pdfVersion(ctx),
	}

	budget := limits.MaxTotalAttachmentSize

	manifest, mErr := extract(ctx, stubs, ManifestAttachmentName, limits, &budget)
	if mErr != nil && !errors.Is(mErr, ErrManifestNotFound) {
		return nil, mErr
	}

	cert.Manifest = manifest

	token, tErr := extract(ctx, stubs, TimestampAttachmentName, limits, &budget)
	if tErr != nil && !errors.Is(tErr, ErrTimestampNotFound) {
		return nil, tErr
	}

	cert.Timestamp = token

	return cert, errors.Join(mErr, tErr)
}

// newConfiguration returns a pdfcpu configuration suitable for an untrusted
// document.
func newConfiguration() *model.Configuration {
	conf := pdfconfig.NewConfiguration()
	conf.Cmd = model.LISTATTACHMENTS
	conf.ValidationMode = model.ValidationRelaxed

	return conf
}

func pdfVersion(ctx *model.Context) string {
	if ctx == nil || ctx.XRefTable == nil {
		return ""
	}

	return ctx.HeaderVersion.String()
}

// isSigned reports whether the document carries a digital signature.
func isSigned(ctx *model.Context) bool {
	if ctx == nil || ctx.XRefTable == nil {
		return false
	}

	return ctx.SignatureExist
}

func attachmentInfos(stubs []model.Attachment) []AttachmentInfo {
	out := make([]AttachmentInfo, 0, len(stubs))
	for _, a := range stubs {
		out = append(out, AttachmentInfo{Name: attachmentName(a), Description: a.Desc})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

	return out
}

// attachmentName returns the name an embedded file is addressed by. pdfcpu
// exposes both the name tree key and the file specification name; they normally
// agree, and the file name wins when they do not.
func attachmentName(a model.Attachment) string {
	if a.FileName != "" {
		return a.FileName
	}

	return a.ID
}

// extract pulls exactly one expected artifact out of the certificate.
//
// Only artifacts whose name matches exactly are considered: no prefix, suffix or
// case insensitive matching is performed, so a hostile document cannot smuggle
// an artifact past the verifier under a lookalike name.
func extract(
	ctx *model.Context,
	stubs []model.Attachment,
	name string,
	limits Limits,
	budget *int64,
) ([]byte, error) {
	ids := matchingIDs(stubs, name)

	switch len(ids) {
	case 0:
		return nil, notFound(name)
	case 1:
	default:
		return nil, fmt.Errorf("%w: %d embedded files are named %q", ErrAmbiguousAttachment, len(ids), name)
	}

	attachments, err := ctx.ExtractAttachments(ids)
	if err != nil {
		return nil, fmt.Errorf("pdf: cannot extract %q: %w", name, err)
	}

	if len(attachments) != 1 {
		return nil, notFound(name)
	}

	a := attachments[0]
	if a.Reader == nil {
		return nil, fmt.Errorf("pdf: embedded file %q carries no data", name)
	}

	allowed := min(limits.MaxAttachmentSize, *budget)

	data, err := io.ReadAll(io.LimitReader(a.Reader, allowed+1))
	if err != nil {
		return nil, fmt.Errorf("pdf: cannot read the embedded file %q: %w", name, err)
	}

	if int64(len(data)) > allowed {
		return nil, fmt.Errorf("%w: %q is larger than %d bytes", ErrAttachmentTooLarge, name, allowed)
	}

	*budget -= int64(len(data))

	return data, nil
}

func matchingIDs(stubs []model.Attachment, name string) []string {
	var ids []string

	for _, a := range stubs {
		if a.FileName == name || (a.FileName == "" && a.ID == name) {
			ids = append(ids, a.ID)
		}
	}

	return ids
}

func notFound(name string) error {
	switch name {
	case ManifestAttachmentName:
		return ErrManifestNotFound
	case TimestampAttachmentName:
		return ErrTimestampNotFound
	default:
		return fmt.Errorf("pdf: the certificate does not embed %q", name)
	}
}

// AttachmentNames returns the names of every embedded file, for diagnostics.
func (c *Certificate) AttachmentNames() []string {
	if c == nil {
		return nil
	}

	names := make([]string, 0, len(c.Attachments))
	for _, a := range c.Attachments {
		names = append(names, a.Name)
	}

	return names
}

// AttachmentSummary renders the embedded file names as a single line, for use
// in a diagnostic message.
func (c *Certificate) AttachmentSummary() string {
	names := c.AttachmentNames()
	if len(names) == 0 {
		return "none"
	}

	return strings.Join(names, ", ")
}

// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

// Package verifier independently verifies Sealway proofs.
//
// # Source of truth
//
// The Sealway certificate is the only authoritative input. Whether a proof is
// supplied as a bundle archive or as a bare certificate, the verifier always
// extracts the proof manifest and the RFC 3161 token from the certificate
// itself. The loose copies a bundle may carry exist for human convenience and
// are never used as a fallback authority, so there is exactly one verification
// path.
//
// # What is verified
//
//	original file
//	  -> SHA-512 of the raw bytes
//	  -> Merkle leaf
//	  -> proof Merkle tree
//	  -> proof Merkle root
//	  -> RFC 3161 timestamp over that root
//	  -> Merkle inclusion proof
//	  -> accumulator Merkle root
//	  -> public blockchain anchors
//
// # What a result means
//
// Every step reports valid, invalid or skipped, and a step whose prerequisites
// were unavailable is always skipped with an explicit reason rather than
// reported as successful. A run is complete when every applicable step was
// performed, partial when something could not be performed, and invalid as soon
// as one step fails.
//
// The verifier establishes cryptographic facts only. It says nothing about
// authorship, ownership, copyright, legal title or the truthfulness of the
// contents of a file.
//
// # Portability
//
// The package is pure Go with no cgo, no shell out and no mandatory filesystem
// access in its cryptographic paths. It reads through io.Reader and io.ReaderAt,
// takes its HTTP client by injection and keeps no global mutable state, so the
// same code backs the command line interface, a desktop application and a
// browser WebAssembly build.
package verifier

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/sealway-hq/sealway-verifier/packages/verifier/bundle"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/proof"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/report"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/timestamp"
)

// Report is the canonical verification report. It is an alias so that callers
// only need to import this package for ordinary use.
type Report = report.Report

// Status is the outcome of a single verification step.
type Status = report.Status

// Result is the aggregated outcome of a verification run.
type Result = report.Result

// ReportSchemaVersion is the version of the report structure, so that a front
// end can state which contract it was built against.
const ReportSchemaVersion = report.SchemaVersion

// Re-exported statuses and results, so that a caller can switch on them without
// importing the report package.
const (
	StatusValid   = report.StatusValid
	StatusInvalid = report.StatusInvalid
	StatusSkipped = report.StatusSkipped

	ResultCompleteValid = report.ResultCompleteValid
	ResultPartialValid  = report.ResultPartialValid
	ResultInvalid       = report.ResultInvalid
)

// Verifier verifies Sealway proofs.
//
// A Verifier holds configuration only and is safe for concurrent use.
type Verifier struct {
	opts *options
}

// New returns a Verifier configured with the given options.
//
// The defaults verify blockchain anchors against public unauthenticated
// endpoints, bound every network operation by a timeout and apply conservative
// resource limits to untrusted input.
func New(opts ...Option) *Verifier {
	return &Verifier{opts: newOptions(opts...)}
}

// Verify verifies the supplied input and returns the canonical report.
//
// The returned error describes an operational failure, such as an unreadable
// input or an unusable archive. A proof that simply does not hold is not an
// error: it is reported through the returned report with a result of invalid.
func (v *Verifier) Verify(ctx context.Context, in Input) (*Report, error) {
	if err := in.validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}

	if in.Bundle != nil {
		return v.VerifyBundle(ctx, in.Bundle, in.BundleSize, in.Sources...)
	}

	return v.VerifyCertificate(ctx, in.Certificate, in.Sources)
}

// VerifyBundle verifies a proof bundle archive, together with any original files
// the caller supplies beside it.
//
// The archive is read without ever extracting anything to disk. Its certificate
// is located deterministically and provides the authoritative manifest and
// timestamp token; the files it carries provide the original sources.
//
// Supplied sources exist for the archive that ships a certificate and nothing
// else, which is what a person is given when the originals were too large to
// travel with the proof. Where the bytes came from is transport: a supplied file
// is hashed and matched exactly as one carried inside the archive is, and is
// never taken on the caller's word.
//
// A supplied file whose name the archive already carries is refused rather than
// resolved. Two different byte streams cannot both be the same certified item,
// and preferring either one would hide that the caller handed over a file which
// is not the certified original.
func (v *Verifier) VerifyBundle(
	ctx context.Context, ra io.ReaderAt, size int64, supplied ...Source,
) (*Report, error) {
	if ra == nil || size <= 0 {
		return nil, fmt.Errorf("%w: a readable proof bundle is required", ErrInvalidInput)
	}

	b, err := bundle.Open(ra, size, v.opts.limits.Bundle)
	if err != nil {
		return nil, err
	}

	entry, err := b.Certificate()
	if err != nil {
		return nil, err
	}

	certData, err := entry.Bytes()
	if err != nil {
		return nil, err
	}

	sources := make([]Source, 0, len(b.Sources())+len(supplied))
	carried := make(map[string]struct{}, len(b.Sources()))

	for _, e := range b.Sources() {
		carried[e.Base()] = struct{}{}

		sources = append(sources, Source{
			Name: e.Base(),
			Size: e.Size,
			// Files carried inside a bundle are asserted by the bundle itself to
			// be part of the proof, so an entry matching no certified item is a
			// finding rather than an unrelated file to ignore.
			Explicit: true,
			Open:     e.Open,
		})
	}

	for _, s := range supplied {
		if _, clash := carried[s.Name]; clash {
			return nil, fmt.Errorf(
				"%w: the archive already carries a file named %q, and two different files cannot "+
					"both be the same certified item", ErrInvalidInput, s.Name)
		}

		sources = append(sources, s)
	}

	r := newRun(v.opts, sources)
	r.bundle = b
	r.certificateName = entry.Name

	return r.execute(ctx, newByteReadSeeker(certData))
}

// VerifyCertificate verifies a Sealway certificate, optionally together with the
// original files it certifies.
//
// Without the original files the source dependent steps are skipped with an
// explicit reason and the run is reported as partial: the certified data is
// shown to be internally consistent, timestamped and anchored, but no claim is
// made about files that were not supplied.
func (v *Verifier) VerifyCertificate(ctx context.Context, rs io.ReadSeeker, sources []Source) (*Report, error) {
	if rs == nil {
		return nil, fmt.Errorf("%w: a readable certificate is required", ErrInvalidInput)
	}

	return newRun(v.opts, sources).execute(ctx, rs)
}

// run carries the state of a single verification.
type run struct {
	opts    *options
	builder *report.Builder
	sources []Source

	bundle          *bundle.Bundle
	certificateName string

	manifest *proof.Manifest
	token    *timestamp.Token
	matches  *matchResult

	// evidence and imprint are what a caller verifying a bare token supplies in
	// place of what a certificate would have carried.
	evidence evidence
	imprint  proof.Hash
}

func newRun(opts *options, sources []Source) *run {
	return &run{opts: opts, builder: report.NewBuilder(), sources: sources}
}

// execute walks the deterministic verification pipeline.
//
// Every stage runs even when an earlier stage failed, as long as it still has
// the inputs it needs. A single mismatching source file must not prevent the
// timestamp from being verified: the report is meant to be as diagnostic as
// possible.
func (r *run) execute(ctx context.Context, rs io.ReadSeeker) (*Report, error) {
	cert, err := r.readCertificate(rs)
	if err != nil {
		return nil, err
	}

	if r.manifest == nil {
		// Without a manifest there is nothing to verify. The failing certificate
		// checks are already recorded, so a report is still returned.
		r.skipRemainingStages("The certificate does not carry a readable proof manifest.")

		return r.builder.Build(), nil
	}

	r.verifySources(ctx)
	r.verifyProofMerkle(ctx)
	r.verifyTimestamp(ctx, cert)
	r.verifyAccumulator()
	r.verifyAnchors(ctx)

	return r.builder.Build(), nil
}

// skipRemainingStages records every downstream stage as skipped when the
// manifest could not be read.
func (r *run) skipRemainingStages(reason string) {
	r.builder.Add(report.SectionSources, "Source files",
		report.NewSkipped("sources.availability", "Original source files", reason))
	r.builder.Add(report.SectionProofMerkle, "Proof Merkle tree",
		report.NewSkipped("proof_merkle.root", "Proof Merkle root", reason))
	r.builder.Add(report.SectionAccumulator, "Accumulator",
		report.NewSkipped("accumulator.inclusion_proof", "Accumulator inclusion proof", reason))
	r.builder.Add(report.SectionAnchors, "Blockchain anchors",
		report.NewSkipped("anchors.availability", "Blockchain anchors", reason))
}

// byteReadSeeker adapts an in-memory document to the reader the certificate
// stage expects.
func newByteReadSeeker(data []byte) io.ReadSeeker { return bytes.NewReader(data) }

// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

// Package report defines the canonical verification report produced by the
// Sealway verifier.
//
// The report is the single contract shared by every front end: the command line
// interface, the desktop application and the future WebAssembly build all
// consume the exact same structure. It is deterministic, JSON serializable and
// free of any presentation concern: it never contains ANSI escape sequences,
// terminal layout or locale dependent formatting.
package report

import (
	"sort"
	"time"
)

// SchemaVersion is the version of the report structure itself. It is bumped
// whenever the JSON shape changes in a way consumers must be aware of.
const SchemaVersion = "1"

// Section identifiers used by the verification pipeline. They are stable and
// safe to switch on from a consumer.
const (
	SectionCertificate = "certificate"
	SectionSources     = "sources"
	SectionProofMerkle = "proof_merkle"
	SectionTimestamp   = "timestamp"
	SectionAccumulator = "accumulator"
	SectionAnchors     = "anchors"
)

// Check is a single verification step.
type Check struct {
	// ID is a stable machine readable identifier, for example
	// "proof_merkle.root" or "sources.item.0".
	ID string `json:"id"`
	// Title is a short human readable label, free of status wording.
	Title string `json:"title"`
	// Status is the outcome of the step.
	Status Status `json:"status"`
	// Message explains the outcome. For a skipped step it always states why the
	// step could not be performed.
	Message string `json:"message"`
	// AffectsCompleteness reports whether this step counts towards a complete
	// verification. It is true for every step that was performed. It is false
	// only for steps that are documented as outside the scope of this version of
	// the verifier, so that skipping them does not downgrade the global result.
	AffectsCompleteness bool `json:"affects_completeness"`
	// Details carries additional machine readable context, such as the expected
	// and the computed value of a mismatching digest.
	Details map[string]string `json:"details,omitempty"`
}

// Section groups the checks of one verification stage.
type Section struct {
	ID     string  `json:"id"`
	Title  string  `json:"title"`
	Checks []Check `json:"checks"`
}

// Certificate carries the identifying metadata read from the certificate.
//
// It is informational: nothing in it is trusted before the corresponding checks
// have been performed.
type Certificate struct {
	PublicID        string     `json:"public_id,omitempty"`
	SchemaVersion   string     `json:"schema_version,omitempty"`
	Title           string     `json:"title,omitempty"`
	Category        string     `json:"category,omitempty"`
	HashAlgorithm   string     `json:"hash_algorithm,omitempty"`
	ItemCount       int        `json:"item_count"`
	TotalSizeBytes  int64      `json:"total_size_bytes"`
	MerkleRoot      string     `json:"merkle_root,omitempty"`
	AccumulatorRoot string     `json:"accumulator_root,omitempty"`
	CreatedAt       *time.Time `json:"created_at,omitempty"`
	TimestampedAt   *time.Time `json:"timestamped_at,omitempty"`
}

// Summary aggregates the check counters of a report.
type Summary struct {
	Total   int `json:"total"`
	Valid   int `json:"valid"`
	Invalid int `json:"invalid"`
	Skipped int `json:"skipped"`
	// SkippedAffectingCompleteness is the number of skipped checks that
	// downgraded the global result from complete to partial.
	SkippedAffectingCompleteness int `json:"skipped_affecting_completeness"`
	// Explanation is a short, presentation free sentence describing what the
	// global result does and does not prove.
	Explanation string `json:"explanation"`
}

// Report is the canonical verification report.
type Report struct {
	SchemaVersion string       `json:"schema_version"`
	Result        Result       `json:"result"`
	Summary       Summary      `json:"summary"`
	Certificate   *Certificate `json:"certificate,omitempty"`
	Sections      []Section    `json:"sections"`
}

// Check returns the check with the given identifier and reports whether it was
// found.
func (r *Report) Check(id string) (Check, bool) {
	if r == nil {
		return Check{}, false
	}

	for _, s := range r.Sections {
		for _, c := range s.Checks {
			if c.ID == id {
				return c, true
			}
		}
	}

	return Check{}, false
}

// Section returns the section with the given identifier and reports whether it
// was found.
func (r *Report) Section(id string) (Section, bool) {
	if r == nil {
		return Section{}, false
	}

	for _, s := range r.Sections {
		if s.ID == id {
			return s, true
		}
	}

	return Section{}, false
}

// Checks returns every check of the report in pipeline order.
func (r *Report) Checks() []Check {
	if r == nil {
		return nil
	}

	out := make([]Check, 0, len(r.Sections)*4)
	for _, s := range r.Sections {
		out = append(out, s.Checks...)
	}

	return out
}

// Valid reports whether the proof was verified without any failing check. It is
// true for both a complete and a partial verification, and callers that need
// the distinction must inspect Result.
func (r *Report) Valid() bool {
	return r != nil && r.Result != ResultInvalid
}

// NewValid returns a check that was performed successfully.
func NewValid(id, title, message string) Check {
	return Check{ID: id, Title: title, Status: StatusValid, Message: message, AffectsCompleteness: true}
}

// NewInvalid returns a check that was performed and failed.
func NewInvalid(id, title, message string) Check {
	return Check{ID: id, Title: title, Status: StatusInvalid, Message: message, AffectsCompleteness: true}
}

// NewSkipped returns a check that could not be performed because the required
// evidence or capability was unavailable. Skipping it downgrades a complete
// verification to a partial one.
func NewSkipped(id, title, reason string) Check {
	return Check{ID: id, Title: title, Status: StatusSkipped, Message: reason, AffectsCompleteness: true}
}

// NewOutOfScope returns a check that is documented as not implemented by this
// version of the verifier. It is reported as skipped so that it is never
// mistaken for a successful verification, but it does not downgrade the global
// result because no evidence is missing.
func NewOutOfScope(id, title, reason string) Check {
	return Check{ID: id, Title: title, Status: StatusSkipped, Message: reason, AffectsCompleteness: false}
}

// WithDetail returns a copy of the check carrying an additional detail.
func (c Check) WithDetail(key, value string) Check {
	details := make(map[string]string, len(c.Details)+1)
	for k, v := range c.Details {
		details[k] = v
	}

	details[key] = value
	c.Details = details

	return c
}

// WithDetails returns a copy of the check carrying additional details.
func (c Check) WithDetails(kv map[string]string) Check {
	if len(kv) == 0 {
		return c
	}

	details := make(map[string]string, len(c.Details)+len(kv))
	for k, v := range c.Details {
		details[k] = v
	}

	for k, v := range kv {
		details[k] = v
	}

	c.Details = details

	return c
}

// DetailKeys returns the detail keys of the check in a deterministic order.
func (c Check) DetailKeys() []string {
	if len(c.Details) == 0 {
		return nil
	}

	keys := make([]string, 0, len(c.Details))
	for k := range c.Details {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	return keys
}

// Builder assembles a report while the verification pipeline runs.
//
// Sections appear in the report in the order in which they were first used, and
// checks appear in the order in which they were added. A Builder is not safe for
// concurrent use.
type Builder struct {
	certificate *Certificate
	sections    []Section
	index       map[string]int
}

// NewBuilder returns an empty report builder.
func NewBuilder() *Builder {
	return &Builder{index: make(map[string]int)}
}

// SetCertificate records the certificate metadata of the report.
func (b *Builder) SetCertificate(c *Certificate) {
	b.certificate = c
}

// Add appends checks to a section, creating the section on first use.
func (b *Builder) Add(sectionID, sectionTitle string, checks ...Check) {
	if len(checks) == 0 {
		return
	}

	i, ok := b.index[sectionID]
	if !ok {
		b.sections = append(b.sections, Section{ID: sectionID, Title: sectionTitle})
		i = len(b.sections) - 1
		b.index[sectionID] = i
	}

	b.sections[i].Checks = append(b.sections[i].Checks, checks...)
}

// Build computes the aggregated result and returns the finished report.
func (b *Builder) Build() *Report {
	r := &Report{
		SchemaVersion: SchemaVersion,
		Certificate:   b.certificate,
		Sections:      b.sections,
	}

	if r.Sections == nil {
		r.Sections = []Section{}
	}

	for _, s := range r.Sections {
		for _, c := range s.Checks {
			r.Summary.Total++

			switch c.Status {
			case StatusValid:
				r.Summary.Valid++
			case StatusInvalid:
				r.Summary.Invalid++
			case StatusSkipped:
				r.Summary.Skipped++

				if c.AffectsCompleteness {
					r.Summary.SkippedAffectingCompleteness++
				}
			}
		}
	}

	switch {
	case r.Summary.Invalid > 0:
		r.Result = ResultInvalid
	case r.Summary.SkippedAffectingCompleteness > 0:
		r.Result = ResultPartialValid
	default:
		r.Result = ResultCompleteValid
	}

	r.Summary.Explanation = explain(r.Result)

	return r
}

func explain(result Result) string {
	switch result {
	case ResultCompleteValid:
		return "All available proof components were successfully verified. " +
			"The supplied files are byte-for-byte identical to the certified hashes, " +
			"those hashes reconstruct the certified proof Merkle root, and that root is " +
			"covered by the verified timestamp and anchoring evidence."
	case ResultPartialValid:
		return "No verification step failed, but at least one step could not be performed " +
			"because the required evidence or capability was unavailable. " +
			"Read the individual steps to see what has and has not been proven."
	case ResultInvalid:
		return "At least one cryptographic or structural verification step failed. " +
			"The proof does not hold for the supplied evidence."
	default:
		return ""
	}
}

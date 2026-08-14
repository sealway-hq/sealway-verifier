// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package report

// Status is the outcome of a single verification step.
//
// A step is never reduced to a boolean, and an absence of proof is never turned
// into a proof of absence: a step that could not reach a conclusion says so
// rather than failing.
type Status string

const (
	// StatusValid means the step was performed and succeeded.
	StatusValid Status = "valid"
	// StatusInvalid means the step was performed and failed.
	StatusInvalid Status = "invalid"
	// StatusSkipped means the step was not attempted, because a prerequisite or
	// a capability was unavailable. The check message always explains why.
	StatusSkipped Status = "skipped"
	// StatusIndeterminate means the step was attempted but could not reach a
	// conclusion, because the evidence it needs is missing, expired, incomplete
	// or impossible to authenticate.
	//
	// It is deliberately distinct from StatusSkipped: skipping means nothing was
	// tried, whereas an indeterminate outcome means the question was asked and
	// the available material does not answer it. Neither may ever be presented
	// as success.
	StatusIndeterminate Status = "indeterminate"
)

// String implements fmt.Stringer.
func (s Status) String() string { return string(s) }

// Result is the aggregated outcome of a whole verification run.
type Result string

const (
	// ResultCompleteValid means every applicable step was performed and no step
	// failed. All evidence required for a full verification was supplied.
	ResultCompleteValid Result = "complete_valid"
	// ResultPartialValid means no performed step failed, but at least one step
	// that contributes to completeness was skipped because the required
	// evidence or capability was unavailable.
	ResultPartialValid Result = "partial_valid"
	// ResultInvalid means at least one cryptographic or structural step failed.
	ResultInvalid Result = "invalid"
)

// String implements fmt.Stringer.
func (r Result) String() string { return string(r) }

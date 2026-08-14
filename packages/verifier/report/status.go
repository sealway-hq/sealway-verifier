// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package report

// Status is the outcome of a single verification step.
//
// A step is never reduced to a boolean: a prerequisite that was unavailable is
// reported as StatusSkipped together with the reason, and is never reported as
// StatusValid.
type Status string

const (
	// StatusValid means the step was performed and succeeded.
	StatusValid Status = "valid"
	// StatusInvalid means the step was performed and failed.
	StatusInvalid Status = "invalid"
	// StatusSkipped means the step could not be performed. The check message
	// always explains why.
	StatusSkipped Status = "skipped"
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

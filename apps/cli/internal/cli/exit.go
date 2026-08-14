// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package cli

import "github.com/sealway-hq/sealway-verifier/packages/verifier/report"

// Exit codes of the command line interface.
//
// A cryptographically invalid proof is a verification outcome, not a tool
// failure: it exits with ExitInvalid, while an unreadable input or an internal
// failure exits with ExitError.
const (
	// ExitCompleteValid means every applicable verification step was performed
	// and none failed.
	ExitCompleteValid = 0
	// ExitInvalid means at least one verification step failed.
	ExitInvalid = 1
	// ExitError means the tool could not run the verification at all.
	ExitError = 2
	// ExitPartialValid means no step failed but at least one could not be
	// performed.
	ExitPartialValid = 3
)

// exitCodeFor maps a verification result to the process exit code.
func exitCodeFor(r report.Result) int {
	switch r {
	case report.ResultCompleteValid:
		return ExitCompleteValid
	case report.ResultPartialValid:
		return ExitPartialValid
	case report.ResultInvalid:
		return ExitInvalid
	default:
		return ExitError
	}
}

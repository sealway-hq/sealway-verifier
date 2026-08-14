// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package report_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealway-hq/sealway-verifier/packages/verifier/report"
)

func TestAggregationCompleteValid(t *testing.T) {
	t.Parallel()

	b := report.NewBuilder()
	b.Add("sources", "Source files", report.NewValid("sources.a", "a", "ok"))
	b.Add("timestamp", "Timestamp", report.NewValid("timestamp.a", "a", "ok"))

	r := b.Build()
	assert.Equal(t, report.ResultCompleteValid, r.Result)
	assert.Equal(t, 2, r.Summary.Valid)
	assert.Equal(t, 0, r.Summary.SkippedAffectingCompleteness)
	assert.True(t, r.Valid())
	assert.NotEmpty(t, r.Summary.Explanation)
}

func TestAggregationPartialWhenSourceChecksSkipped(t *testing.T) {
	t.Parallel()

	b := report.NewBuilder()
	b.Add("sources", "Source files", report.NewSkipped("sources.a", "a", "no file was provided"))
	b.Add("timestamp", "Timestamp", report.NewValid("timestamp.a", "a", "ok"))

	r := b.Build()
	assert.Equal(t, report.ResultPartialValid, r.Result)
	assert.Equal(t, 1, r.Summary.SkippedAffectingCompleteness)
	assert.True(t, r.Valid())
}

func TestAggregationPartialWhenNetworkChecksSkipped(t *testing.T) {
	t.Parallel()

	b := report.NewBuilder()
	b.Add("anchors", "Anchors", report.NewSkipped("anchors.polygon", "Polygon", "network disabled"))
	b.Add("timestamp", "Timestamp", report.NewValid("timestamp.a", "a", "ok"))

	assert.Equal(t, report.ResultPartialValid, b.Build().Result)
}

// TestOutOfScopeSkipDoesNotDowngrade pins the distinction between evidence that
// is missing and a check this version simply does not implement. Only the former
// makes a verification partial.
func TestOutOfScopeSkipDoesNotDowngrade(t *testing.T) {
	t.Parallel()

	b := report.NewBuilder()
	b.Add("timestamp", "Timestamp",
		report.NewValid("timestamp.signature", "CMS signature", "ok"),
		report.NewOutOfScope("timestamp.qualified", "Qualified", "not implemented"))

	r := b.Build()
	assert.Equal(t, report.ResultCompleteValid, r.Result)
	assert.Equal(t, 1, r.Summary.Skipped)
	assert.Equal(t, 0, r.Summary.SkippedAffectingCompleteness)
}

// TestIndeterminateNeverYieldsComplete pins the rule that an absence of proof is
// neither success nor failure: it downgrades the result without invalidating it.
func TestIndeterminateNeverYieldsComplete(t *testing.T) {
	t.Parallel()

	b := report.NewBuilder()
	b.Add("timestamp", "Timestamp",
		report.NewValid("timestamp.signature", "CMS signature", "ok"),
		report.NewIndeterminate("timestamp.qualified", "Qualified status",
			"the trusted list could not be authenticated"))

	r := b.Build()
	assert.Equal(t, report.ResultPartialValid, r.Result)
	assert.Equal(t, 1, r.Summary.Indeterminate)
	assert.Zero(t, r.Summary.Invalid)
	assert.Zero(t, r.Summary.Skipped)
	assert.True(t, r.Valid(), "indeterminate is not a failure")
}

// TestInvalidBeatsIndeterminate keeps a real failure visible even when another
// step could not conclude.
func TestInvalidBeatsIndeterminate(t *testing.T) {
	t.Parallel()

	b := report.NewBuilder()
	b.Add("a", "A",
		report.NewIndeterminate("a.1", "one", "no material"),
		report.NewInvalid("a.2", "two", "digest mismatch"))

	r := b.Build()
	assert.Equal(t, report.ResultInvalid, r.Result)
	assert.Equal(t, 1, r.Summary.Indeterminate)
	assert.Equal(t, 1, r.Summary.Invalid)
	assert.False(t, r.Valid())
}

// TestIndeterminateIsDistinctFromSkipped guards the distinction the two statuses
// exist to express.
func TestIndeterminateIsDistinctFromSkipped(t *testing.T) {
	t.Parallel()

	indeterminate := report.NewIndeterminate("a", "A", "attempted, no conclusion")
	skipped := report.NewSkipped("b", "B", "not attempted")

	assert.Equal(t, report.StatusIndeterminate, indeterminate.Status)
	assert.Equal(t, report.StatusSkipped, skipped.Status)
	assert.NotEqual(t, indeterminate.Status, skipped.Status)
	assert.Equal(t, "indeterminate", report.StatusIndeterminate.String())

	// Both must always say why.
	assert.NotEmpty(t, indeterminate.Message)
	assert.NotEmpty(t, skipped.Message)

	// Both count towards completeness, so neither can be silently ignored.
	assert.True(t, indeterminate.AffectsCompleteness)
	assert.True(t, skipped.AffectsCompleteness)
}

func TestAggregationInvalidWins(t *testing.T) {
	t.Parallel()

	b := report.NewBuilder()
	b.Add("sources", "Source files",
		report.NewValid("sources.a", "a", "ok"),
		report.NewInvalid("sources.b", "b", "digest mismatch"),
		report.NewSkipped("sources.c", "c", "not provided"))

	r := b.Build()
	assert.Equal(t, report.ResultInvalid, r.Result)
	assert.Equal(t, 1, r.Summary.Invalid)
	assert.False(t, r.Valid())
}

func TestEmptyReportIsCompleteValid(t *testing.T) {
	t.Parallel()

	r := report.NewBuilder().Build()
	assert.Equal(t, report.ResultCompleteValid, r.Result)
	assert.NotNil(t, r.Sections)
	assert.Empty(t, r.Sections)
}

func TestSectionsKeepFirstUseOrder(t *testing.T) {
	t.Parallel()

	b := report.NewBuilder()
	b.Add("b", "Second", report.NewValid("b.1", "one", "ok"))
	b.Add("a", "First", report.NewValid("a.1", "one", "ok"))
	b.Add("b", "Second", report.NewValid("b.2", "two", "ok"))

	r := b.Build()
	require.Len(t, r.Sections, 2)
	assert.Equal(t, "b", r.Sections[0].ID)
	assert.Equal(t, "a", r.Sections[1].ID)
	assert.Len(t, r.Sections[0].Checks, 2)

	// Checks keep the order in which they were added.
	assert.Equal(t, "b.1", r.Sections[0].Checks[0].ID)
	assert.Equal(t, "b.2", r.Sections[0].Checks[1].ID)
}

func TestAddWithoutChecksCreatesNoSection(t *testing.T) {
	t.Parallel()

	b := report.NewBuilder()
	b.Add("a", "A")

	assert.Empty(t, b.Build().Sections)
}

func TestLookups(t *testing.T) {
	t.Parallel()

	b := report.NewBuilder()
	b.Add("a", "A", report.NewValid("a.1", "one", "ok"))

	r := b.Build()

	c, ok := r.Check("a.1")
	require.True(t, ok)
	assert.Equal(t, report.StatusValid, c.Status)

	_, ok = r.Check("missing")
	assert.False(t, ok)

	s, ok := r.Section("a")
	require.True(t, ok)
	assert.Len(t, s.Checks, 1)

	_, ok = r.Section("missing")
	assert.False(t, ok)

	assert.Len(t, r.Checks(), 1)

	var nilReport *report.Report

	_, ok = nilReport.Check("a.1")
	assert.False(t, ok)
	_, ok = nilReport.Section("a")
	assert.False(t, ok)
	assert.Nil(t, nilReport.Checks())
	assert.False(t, nilReport.Valid())
}

func TestDetailsAreImmutableAndOrdered(t *testing.T) {
	t.Parallel()

	base := report.NewValid("a.1", "one", "ok")
	withOne := base.WithDetail("zeta", "1")
	withTwo := withOne.WithDetail("alpha", "2")

	assert.Nil(t, base.Details)
	assert.Len(t, withOne.Details, 1)
	assert.Len(t, withTwo.Details, 2)
	assert.Equal(t, []string{"alpha", "zeta"}, withTwo.DetailKeys())
	assert.Nil(t, base.DetailKeys())

	merged := base.WithDetails(map[string]string{"x": "1", "y": "2"})
	assert.Len(t, merged.Details, 2)
	assert.Nil(t, base.WithDetails(nil).Details)
}

// TestJSONIsDeterministic guards the report contract: the same report must
// always serialize to exactly the same bytes, because it is a public API.
func TestJSONIsDeterministic(t *testing.T) {
	t.Parallel()

	build := func() *report.Report {
		b := report.NewBuilder()
		b.SetCertificate(&report.Certificate{PublicID: "SW-2026-TEST0001", ItemCount: 2})
		b.Add("sources", "Source files",
			report.NewValid("sources.a", "a", "ok").
				WithDetails(map[string]string{"z": "1", "a": "2", "m": "3"}),
			report.NewSkipped("sources.b", "b", "not provided"))

		return b.Build()
	}

	first, err := json.Marshal(build())
	require.NoError(t, err)

	for range 20 {
		again, err := json.Marshal(build())
		require.NoError(t, err)
		require.Equal(t, string(first), string(again))
	}

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(first, &decoded))
	assert.Equal(t, report.SchemaVersion, decoded["schema_version"])
	assert.Equal(t, "partial_valid", decoded["result"])
}

func TestStatusAndResultStrings(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "valid", report.StatusValid.String())
	assert.Equal(t, "invalid", report.StatusInvalid.String())
	assert.Equal(t, "skipped", report.StatusSkipped.String())
	assert.Equal(t, "complete_valid", report.ResultCompleteValid.String())
	assert.Equal(t, "partial_valid", report.ResultPartialValid.String())
	assert.Equal(t, "invalid", report.ResultInvalid.String())
}

// TestSkippedChecksAlwaysCarryAReason encodes the rule that a missing
// prerequisite is never reported without saying why.
func TestSkippedChecksAlwaysCarryAReason(t *testing.T) {
	t.Parallel()

	for _, c := range []report.Check{
		report.NewSkipped("a", "A", "because"),
		report.NewOutOfScope("b", "B", "because"),
	} {
		assert.Equal(t, report.StatusSkipped, c.Status)
		assert.NotEmpty(t, c.Message)
	}
}

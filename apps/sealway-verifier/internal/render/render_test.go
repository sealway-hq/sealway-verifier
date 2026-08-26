// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package render_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealway-hq/sealway-verifier/apps/sealway-verifier/internal/render"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/report"
)

func sample() *report.Report {
	b := report.NewBuilder()
	b.SetCertificate(&report.Certificate{
		PublicID:  "SW-2026-D8DY92C8",
		Title:     "Discours de Steve Jobs",
		ItemCount: 1,
	})
	b.Add(report.SectionCertificate, "Certificate",
		report.NewValid("certificate.manifest", "Embedded proof manifest", "extracted"))
	b.Add(report.SectionSources, "Source files",
		report.NewSkipped("sources.availability", "Original source files",
			"No original source file was provided, so the SHA-512 of the certified items could not "+
				"be independently recomputed."))
	b.Add(report.SectionTimestamp, "Qualified timestamp",
		report.NewInvalid("timestamp.imprint", "Message imprint matches the proof root",
			"The message imprint does not equal the certified proof Merkle root.").
			WithDetails(map[string]string{"expected": "aaaa", "computed": "bbbb"}))

	return b.Build()
}

func TestHumanRendersEveryStage(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	require.NoError(t, render.Human(&buf, sample(), render.Options{}))

	out := buf.String()

	assert.Contains(t, out, "Sealway Proof Verification")
	assert.Contains(t, out, "SW-2026-D8DY92C8")
	assert.Contains(t, out, "Discours de Steve Jobs")
	assert.Contains(t, out, "Certificate")
	assert.Contains(t, out, "Source files")
	assert.Contains(t, out, "Qualified timestamp")
	assert.Contains(t, out, "VALID")
	assert.Contains(t, out, "SKIPPED")
	assert.Contains(t, out, "INVALID")
	assert.Contains(t, out, "Result")
	assert.Contains(t, out, "INVALID")
	assert.Contains(t, out, "3 check(s): 1 valid, 1 invalid, 0 indeterminate, 1 skipped.")
}

// TestHumanAlwaysExplainsSkipsAndFailures pins the promise that a skipped or
// failing step never appears without its reason.
//
// Assertions run against whitespace-normalised output: the promise is about the
// text being present, not about where the wrapper happens to break a line.
func TestHumanAlwaysExplainsSkipsAndFailures(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	require.NoError(t, render.Human(&buf, sample(), render.Options{}))

	out := flatten(buf.String())
	assert.Contains(t, out, "No original source file was provided")
	assert.Contains(t, out, "does not equal the certified proof Merkle root")

	// Details of a failing check are shown so the user can act on them.
	assert.Contains(t, out, "expected: aaaa")
	assert.Contains(t, out, "computed: bbbb")
}

// flatten collapses every run of whitespace into a single space, so that
// assertions describe content rather than layout.
func flatten(s string) string { return strings.Join(strings.Fields(s), " ") }

func TestHumanHidesSuccessfulMessagesUnlessVerbose(t *testing.T) {
	t.Parallel()

	var quiet, verbose bytes.Buffer
	require.NoError(t, render.Human(&quiet, sample(), render.Options{}))
	require.NoError(t, render.Human(&verbose, sample(), render.Options{Verbose: true}))

	assert.NotContains(t, quiet.String(), "extracted")
	assert.Contains(t, verbose.String(), "extracted")
}

// TestStatusIsReadableWithoutColor is the accessibility requirement: colour is
// never the only carrier of a status.
func TestStatusIsReadableWithoutColor(t *testing.T) {
	t.Parallel()

	var plain bytes.Buffer
	require.NoError(t, render.Human(&plain, sample(), render.Options{Color: false}))

	assert.NotContains(t, plain.String(), "\x1b[")
	assert.Contains(t, plain.String(), "VALID")
	assert.Contains(t, plain.String(), "SKIPPED")
	assert.Contains(t, plain.String(), "INVALID")
}

func TestColorIsEmittedWhenEnabled(t *testing.T) {
	t.Parallel()

	var colored bytes.Buffer
	require.NoError(t, render.Human(&colored, sample(), render.Options{Color: true}))

	out := colored.String()
	assert.Contains(t, out, "\x1b[32m") // green
	assert.Contains(t, out, "\x1b[33m") // yellow
	assert.Contains(t, out, "\x1b[31m") // red
	assert.Contains(t, out, "\x1b[0m")

	// Stripping the escape sequences must leave the same readable text.
	assert.Contains(t, stripANSI(out), "VALID")
}

func stripANSI(s string) string {
	var out strings.Builder

	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}

			continue
		}

		out.WriteByte(s[i])
	}

	return out.String()
}

// TestIndeterminateIsRenderedDistinctly checks the reader can tell "not
// attempted" from "attempted and inconclusive", which is the whole point of the
// two statuses being separate.
func TestIndeterminateIsRenderedDistinctly(t *testing.T) {
	t.Parallel()

	b := report.NewBuilder()
	b.Add("timestamp", "Qualified timestamp",
		report.NewSkipped("a.skipped", "Not attempted", "blockchain verification was disabled"),
		report.NewIndeterminate("a.indeterminate", "Attempted, inconclusive",
			"the trusted list could not be authenticated").
			WithDetail("trust_list", "ES"))

	var buf bytes.Buffer
	require.NoError(t, render.Human(&buf, b.Build(), render.Options{}))

	out := flatten(buf.String())

	assert.Contains(t, out, "SKIPPED Not attempted")
	assert.Contains(t, out, "INDETERMINATE Attempted, inconclusive")
	assert.Contains(t, out, "the trusted list could not be authenticated")

	// Details are shown for an indeterminate step too, because they say what was
	// missing.
	assert.Contains(t, out, "trust_list: ES")

	assert.Contains(t, out, "0 valid, 0 invalid, 1 indeterminate, 1 skipped")
}

// TestStatusLabelsShareOneColumn keeps the titles aligned whatever the status,
// including the longest label.
func TestStatusLabelsShareOneColumn(t *testing.T) {
	t.Parallel()

	b := report.NewBuilder()
	b.Add("s", "Section",
		report.NewValid("a", "Alpha", "ok"),
		report.NewInvalid("b", "Beta", "no"),
		report.NewSkipped("c", "Gamma", "no"),
		report.NewIndeterminate("d", "Delta", "no"))

	var buf bytes.Buffer
	require.NoError(t, render.Human(&buf, b.Build(), render.Options{}))

	var columns []int

	for _, line := range strings.Split(buf.String(), "\n") {
		for _, title := range []string{"Alpha", "Beta", "Gamma", "Delta"} {
			if strings.Contains(line, title) {
				columns = append(columns, strings.Index(line, title))
			}
		}
	}

	require.Len(t, columns, 4)

	for _, c := range columns {
		assert.Equal(t, columns[0], c, "titles must start in the same column")
	}
}

func TestResultLabels(t *testing.T) {
	t.Parallel()

	for result, want := range map[report.Result]string{
		report.ResultCompleteValid: "COMPLETE VALID",
		report.ResultPartialValid:  "PARTIAL VALID",
		report.ResultInvalid:       "INVALID",
	} {
		b := report.NewBuilder()

		switch result {
		case report.ResultCompleteValid:
			b.Add("a", "A", report.NewValid("a.1", "one", "ok"))
		case report.ResultPartialValid:
			b.Add("a", "A", report.NewSkipped("a.1", "one", "missing"))
		case report.ResultInvalid:
			b.Add("a", "A", report.NewInvalid("a.1", "one", "broken"))
		}

		var buf bytes.Buffer
		require.NoError(t, render.Human(&buf, b.Build(), render.Options{}))
		assert.Contains(t, buf.String(), want)
	}
}

func TestHumanWrapsLongMessages(t *testing.T) {
	t.Parallel()

	b := report.NewBuilder()
	b.Add("a", "A", report.NewSkipped("a.1", "one", strings.Repeat("word ", 60)))

	var buf bytes.Buffer
	require.NoError(t, render.Human(&buf, b.Build(), render.Options{}))

	for _, line := range strings.Split(buf.String(), "\n") {
		assert.LessOrEqual(t, len(line), render.LineWidth+2, "line too long: %q", line)
	}
}

func TestHumanHandlesReportWithoutCertificate(t *testing.T) {
	t.Parallel()

	b := report.NewBuilder()
	b.Add("a", "A", report.NewValid("a.1", "one", "ok"))

	var buf bytes.Buffer
	require.NoError(t, render.Human(&buf, b.Build(), render.Options{}))
	assert.Contains(t, buf.String(), "Sealway Proof Verification")
}

func TestHumanReportsWriteFailures(t *testing.T) {
	t.Parallel()

	err := render.Human(failingWriter{}, sample(), render.Options{})
	assert.Error(t, err)
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, assert.AnError }

// TestJSONIsTheCanonicalReport checks the machine readable output is the report
// itself, with nothing added and nothing removed.
func TestJSONIsTheCanonicalReport(t *testing.T) {
	t.Parallel()

	r := sample()

	var buf bytes.Buffer
	require.NoError(t, render.JSON(&buf, r))

	var decoded report.Report
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))
	assert.Equal(t, *r, decoded)

	canonical, err := json.Marshal(r)
	require.NoError(t, err)

	compact := bytes.Buffer{}
	require.NoError(t, json.Compact(&compact, buf.Bytes()))
	assert.JSONEq(t, string(canonical), compact.String())
}

func TestJSONIsIndentedAndNewlineTerminated(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	require.NoError(t, render.JSON(&buf, sample()))

	assert.Contains(t, buf.String(), "\n  \"result\":")
	assert.True(t, strings.HasSuffix(buf.String(), "\n"))
}

func TestJSONReportsWriteFailures(t *testing.T) {
	t.Parallel()

	assert.Error(t, render.JSON(failingWriter{}, sample()))
}

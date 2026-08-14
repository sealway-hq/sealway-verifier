// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

// Package render turns a verification report into terminal output.
//
// Rendering is the only place that knows about colors, wrapping and layout: the
// report itself carries no presentation concern, so the same report can be
// rendered by a desktop application or a web front end without change.
package render

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/sealway-hq/sealway-verifier/packages/verifier/report"
)

// LineWidth is the column at which messages are wrapped.
const LineWidth = 80

// Status labels are padded to a fixed width so that titles line up. The widest
// label is INDETERMINATE.
const statusWidth = len("INDETERMINATE")

// messageIndent is the column at which a check message starts: two leading
// spaces, the status label and one separating space.
const messageIndent = 2 + statusWidth + 1

var indent = strings.Repeat(" ", messageIndent)

// JSON writes the canonical report as indented JSON.
//
// This is the machine readable contract of the command line interface: it is the
// report itself, with nothing added and nothing removed.
func JSON(w io.Writer, r *report.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)

	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("render: cannot write the report: %w", err)
	}

	return nil
}

// Options configures the human readable rendering.
type Options struct {
	// Color enables ANSI colors. Status is always also conveyed by its label, so
	// output remains fully readable without them.
	Color bool
	// Verbose shows the explanation of successful checks as well.
	Verbose bool
}

// Human writes the report as a human readable summary.
func Human(w io.Writer, r *report.Report, opts Options) error {
	p := &printer{w: w, color: opts.Color, verbose: opts.Verbose}

	p.header(r)

	for _, s := range r.Sections {
		p.section(s)
	}

	p.result(r)

	return p.err
}

type printer struct {
	w       io.Writer
	color   bool
	verbose bool
	err     error
}

func (p *printer) printf(format string, args ...any) {
	if p.err != nil {
		return
	}

	if _, err := fmt.Fprintf(p.w, format, args...); err != nil {
		p.err = err
	}
}

func (p *printer) header(r *report.Report) {
	p.printf("%s\n", p.bold("Sealway Proof Verification"))

	if r.Certificate == nil {
		p.printf("\n")

		return
	}

	c := r.Certificate
	if c.PublicID != "" {
		p.printf("%s\n", c.PublicID)
	}

	if c.Title != "" {
		p.printf("%s\n", c.Title)
	}

	p.printf("\n")
}

func (p *printer) section(s report.Section) {
	p.printf("%s\n", p.bold(s.Title))

	for _, c := range s.Checks {
		p.check(c)
	}

	p.printf("\n")
}

func (p *printer) check(c report.Check) {
	p.printf("  %s %s\n", p.status(c.Status), c.Title)

	show := c.Status != report.StatusValid || p.verbose
	if show && c.Message != "" {
		for _, line := range wrap(c.Message, LineWidth-messageIndent) {
			p.printf("%s%s\n", indent, line)
		}
	}

	// Details carry the values a reader needs to redo the comparison, so they
	// are shown whenever the step did not simply succeed.
	if c.Status == report.StatusInvalid || c.Status == report.StatusIndeterminate {
		p.details(c)
	}
}

func (p *printer) details(c report.Check) {
	for _, k := range c.DetailKeys() {
		p.printf("%s%s: %s\n", indent, k, c.Details[k])
	}
}

func (p *printer) result(r *report.Report) {
	p.printf("%s\n", p.bold("Result"))
	p.printf("  %s\n\n", p.resultLabel(r.Result))

	for _, line := range wrap(r.Summary.Explanation, LineWidth) {
		p.printf("%s\n", line)
	}

	p.printf("\n%d check(s): %d valid, %d invalid, %d indeterminate, %d skipped.\n",
		r.Summary.Total, r.Summary.Valid, r.Summary.Invalid,
		r.Summary.Indeterminate, r.Summary.Skipped)
}

// status renders a check status. The label is always written out, so the output
// never depends on color to be understood.
func (p *printer) status(s report.Status) string {
	label, code := "UNKNOWN", yellow

	switch s {
	case report.StatusValid:
		label, code = "VALID", green
	case report.StatusInvalid:
		label, code = "INVALID", red
	case report.StatusSkipped:
		label, code = "SKIPPED", yellow
	case report.StatusIndeterminate:
		label, code = "INDETERMINATE", yellow
	}

	// The label is padded before colouring so that the escape sequences never
	// count towards the column width.
	return p.colorize(fmt.Sprintf("%-*s", statusWidth, label), code)
}

func (p *printer) resultLabel(r report.Result) string {
	switch r {
	case report.ResultCompleteValid:
		return p.colorize("COMPLETE VALID", green)
	case report.ResultPartialValid:
		return p.colorize("PARTIAL VALID", yellow)
	case report.ResultInvalid:
		return p.colorize("INVALID", red)
	default:
		return string(r)
	}
}

const (
	reset  = "\x1b[0m"
	red    = "\x1b[31m"
	green  = "\x1b[32m"
	yellow = "\x1b[33m"
	bold   = "\x1b[1m"
)

func (p *printer) colorize(s, code string) string {
	if !p.color {
		return s
	}

	return code + s + reset
}

func (p *printer) bold(s string) string { return p.colorize(s, bold) }

// wrap breaks a message into lines of at most width characters, without
// splitting words.
func wrap(s string, width int) []string {
	if s == "" {
		return nil
	}

	if width < 20 {
		width = 20
	}

	words := strings.Fields(s)
	if len(words) == 0 {
		return nil
	}

	var (
		lines []string
		line  strings.Builder
	)

	for _, word := range words {
		switch {
		case line.Len() == 0:
			line.WriteString(word)
		case line.Len()+1+len(word) <= width:
			line.WriteByte(' ')
			line.WriteString(word)
		default:
			lines = append(lines, line.String())
			line.Reset()
			line.WriteString(word)
		}
	}

	if line.Len() > 0 {
		lines = append(lines, line.String())
	}

	return lines
}

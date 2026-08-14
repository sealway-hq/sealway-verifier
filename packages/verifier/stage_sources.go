// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package verifier

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/sealway-hq/sealway-verifier/packages/verifier/proof"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/report"
)

const sectionSourcesTitle = "Source files"

// verifySources recomputes the SHA-512 of every supplied original file and
// compares it with the certified leaf.
//
// A file that was not supplied makes its item skipped, never valid and never
// invalid: the verifier cannot say anything about a file it has not seen.
func (r *run) verifySources(ctx context.Context) {
	reportProgress(r.opts.progress, Progress{Stage: StageSources, Total: len(r.sources)})

	items := r.manifest.ItemsByPosition()

	if len(r.sources) == 0 {
		r.builder.Add(report.SectionSources, sectionSourcesTitle,
			report.NewSkipped("sources.availability", "Original source files",
				fmt.Sprintf("No original source file was provided, so the SHA-512 of the %d certified "+
					"item(s) could not be independently recomputed.", len(items))))

		return
	}

	if err := ctx.Err(); err != nil {
		r.builder.Add(report.SectionSources, sectionSourcesTitle,
			report.NewSkipped("sources.availability", "Original source files",
				"Verification was cancelled before the source files were read: "+err.Error()))

		return
	}

	r.matches = matchSources(items, r.sources, r.opts.progress)

	r.addAvailabilityCheck(items)
	r.addItemChecks(items)
	r.addUnmatchedChecks()
}

func (r *run) addAvailabilityCheck(items []proof.Item) {
	const (
		id    = "sources.availability"
		title = "Original source files"
	)

	provided := len(r.matches.byPosition)

	details := map[string]string{
		"certified_items":   strconv.Itoa(len(items)),
		"files_provided":    strconv.Itoa(len(r.sources)),
		"items_matched":     strconv.Itoa(provided),
		"files_disregarded": strconv.Itoa(r.matches.ignored),
	}

	switch {
	case provided == len(items):
		r.builder.Add(report.SectionSources, sectionSourcesTitle,
			report.NewValid(id, title, fmt.Sprintf(
				"All %d certified item(s) were matched with a supplied file.", len(items))).
				WithDetails(details))
	case provided == 0:
		r.builder.Add(report.SectionSources, sectionSourcesTitle,
			report.NewSkipped(id, title, fmt.Sprintf(
				"None of the %d supplied file(s) corresponds to a certified item, so no source digest "+
					"could be recomputed.", len(r.sources))).
				WithDetails(details))
	default:
		r.builder.Add(report.SectionSources, sectionSourcesTitle,
			report.NewSkipped(id, title, fmt.Sprintf(
				"Only %d of the %d certified item(s) were matched with a supplied file.",
				provided, len(items))).
				WithDetails(details))
	}
}

func (r *run) addItemChecks(items []proof.Item) {
	for _, it := range items {
		id := "sources.item." + strconv.Itoa(it.Position)
		title := itemTitle(it)

		m, ok := r.matches.byPosition[it.Position]
		if !ok {
			r.builder.Add(report.SectionSources, sectionSourcesTitle,
				report.NewSkipped(id, title,
					"The original file was not provided, so its SHA-512 could not be recomputed and "+
						"compared with the certified leaf."))

			continue
		}

		if m.err != nil {
			r.builder.Add(report.SectionSources, sectionSourcesTitle,
				report.NewSkipped(id, title,
					"The supplied file could not be read: "+m.err.Error()))

			continue
		}

		r.builder.Add(report.SectionSources, sectionSourcesTitle, itemCheck(id, title, it, m))
	}
}

func itemCheck(id, title string, it proof.Item, m sourceMatch) report.Check {
	if !equalHash(m.hash, it.LeafHash) {
		return report.NewInvalid(id, title, fmt.Sprintf(
			"The SHA-512 of %q does not match the certified leaf. The supplied file is not the "+
				"certified file.", m.source.Name)).
			WithDetails(map[string]string{
				"supplied_file": m.source.Name,
				"expected":      it.LeafHash.String(),
				"computed":      proof.Hash(m.hash).String(),
				"matched_by":    string(m.kind),
			})
	}

	check := report.NewValid(id, title, fmt.Sprintf(
		"The SHA-512 of %q matches the certified leaf: the supplied file is byte-for-byte identical "+
			"to the certified file.", m.source.Name)).
		WithDetails(map[string]string{
			"supplied_file": m.source.Name,
			"sha512":        it.LeafHash.String(),
			"matched_by":    string(m.kind),
		})

	if it.SizeBytes > 0 && m.source.Size >= 0 && m.source.Size != it.SizeBytes {
		// The digest already proves the content; a disagreeing declared size is
		// only worth recording as context.
		check = check.WithDetail("declared_size_bytes", strconv.FormatInt(it.SizeBytes, 10))
		check = check.WithDetail("supplied_size_bytes", strconv.FormatInt(m.source.Size, 10))
	}

	return check
}

// addUnmatchedChecks reports supplied files that correspond to no certified
// item.
//
// A file the caller explicitly designated as part of the proof, or that a bundle
// carries in its files directory, is asserted to belong to the proof. When it
// matches no certified item that assertion is wrong, which is a finding rather
// than something to ignore.
func (r *run) addUnmatchedChecks() {
	const (
		id    = "sources.unmatched"
		title = "Supplied files"
	)

	var problems []string

	if len(r.matches.unmatched) > 0 {
		problems = append(problems,
			"the following supplied file(s) correspond to no certified item: "+
				strings.Join(quoteAll(r.matches.unmatched), ", "))
	}

	if len(r.matches.duplicates) > 0 {
		problems = append(problems,
			"the following supplied file(s) claim a certified name already taken by another file: "+
				strings.Join(quoteAll(r.matches.duplicates), ", "))
	}

	for _, f := range r.matches.failed {
		problems = append(problems, fmt.Sprintf("%q could not be read: %s", f.name, f.err))
	}

	if len(problems) == 0 {
		return
	}

	r.builder.Add(report.SectionSources, sectionSourcesTitle,
		report.NewInvalid(id, title,
			"Some supplied files do not belong to this proof: "+strings.Join(problems, "; ")+"."))
}

func itemTitle(it proof.Item) string {
	if it.Filename != "" {
		return it.Filename
	}

	return "Item " + strconv.Itoa(it.Position)
}

func quoteAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, strconv.Quote(s))
	}

	return out
}

// verifiedLeaves returns the recomputed digests of the certified items in leaf
// order, and reports whether every item was covered by a verified source file.
//
// Only digests that actually matched their certified leaf are returned, because
// the proof Merkle tree must be rebuilt from verified sources, never from
// unverified manifest data.
func (r *run) verifiedLeaves(items []proof.Item) (leaves [][]byte, complete bool) {
	if r.matches == nil {
		return nil, false
	}

	leaves = make([][]byte, 0, len(items))

	for _, it := range items {
		m, ok := r.matches.byPosition[it.Position]
		if !ok || m.err != nil || !equalHash(m.hash, it.LeafHash) {
			return nil, false
		}

		leaves = append(leaves, m.hash)
	}

	return leaves, len(leaves) == len(items) && len(items) > 0
}

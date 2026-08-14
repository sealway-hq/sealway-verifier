// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package verifier

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/sealway-hq/sealway-verifier/packages/verifier/anchor"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/proof"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/report"
)

const sectionAnchorsTitle = "Blockchain anchors"

// verifyAnchors checks that each declared public blockchain transaction really
// carries the accumulator Merkle root.
//
// A transaction that exists proves nothing on its own. What is verified is the
// payload actually anchored on chain, read from an unauthenticated public
// endpoint, and compared with the accumulator root the manifest declares.
func (r *run) verifyAnchors(ctx context.Context) {
	reportProgress(r.opts.progress, Progress{Stage: StageAnchors})

	anchors := r.manifest.Anchors()
	expected := r.manifest.Notarization.AccumulatorRoot

	if len(anchors) == 0 {
		r.builder.Add(report.SectionAnchors, sectionAnchorsTitle,
			report.NewSkipped("anchors.availability", "Blockchain anchors",
				"The manifest declares no blockchain anchor, so nothing could be checked on chain."))

		return
	}

	if !r.opts.verifyBlockchain {
		r.skipAllAnchors(anchors,
			"Blockchain verification was disabled, so the anchored payload was not read on chain.")

		return
	}

	if expected.IsZero() {
		r.skipAllAnchors(anchors,
			"The manifest declares no accumulator Merkle root, so there is nothing to look for on chain.")

		return
	}

	for _, a := range anchors {
		r.builder.Add(report.SectionAnchors, sectionAnchorsTitle, r.verifyAnchor(ctx, a, expected))
	}
}

func (r *run) skipAllAnchors(anchors []proof.Anchor, reason string) {
	for _, a := range anchors {
		r.builder.Add(report.SectionAnchors, sectionAnchorsTitle,
			report.NewSkipped(anchorCheckID(a), anchorTitle(a), reason).
				WithDetail("transaction_id", a.TransactionID))
	}
}

func (r *run) verifyAnchor(ctx context.Context, a proof.Anchor, expected proof.Hash) report.Check {
	id, title := anchorCheckID(a), anchorTitle(a)
	network := strings.ToLower(strings.TrimSpace(a.ProviderName))

	details := map[string]string{
		"network":        network,
		"transaction_id": a.TransactionID,
		"expected_root":  expected.String(),
	}

	if a.BlockNumber > 0 {
		details["declared_block"] = strconv.FormatUint(a.BlockNumber, 10)
	}

	v, ok := r.opts.anchorRegistry.Verifier(network)
	if !ok {
		return report.NewSkipped(id, title, fmt.Sprintf(
			"No verifier is available for the %q network, so its anchored payload could not be read. "+
				"Supported networks: %s.", network, strings.Join(sortedNetworks(r.opts.anchorRegistry), ", "))).
			WithDetails(details)
	}

	details["endpoint"] = v.Endpoint()

	lookupCtx, cancel := context.WithTimeout(ctx, r.opts.networkTimeout)
	defer cancel()

	res, err := v.Verify(lookupCtx, anchor.Anchor{
		Network:       network,
		TransactionID: a.TransactionID,
		BlockNumber:   a.BlockNumber,
		BlockHash:     a.BlockHash,
	}, expected.Bytes())
	if err != nil {
		return anchorErrorCheck(id, title, network, err, details)
	}

	if res.BlockNumber > 0 {
		details["observed_block"] = strconv.FormatUint(res.BlockNumber, 10)
	}

	details["anchored_payload"] = proof.Hash(res.Payload).String()
	details["match"] = string(res.Match)

	if !res.Verified {
		return report.NewInvalid(id, title, fmt.Sprintf(
			"The %s transaction exists but its anchored payload does not carry the certified "+
				"accumulator Merkle root.", network)).
			WithDetails(details)
	}

	message := fmt.Sprintf(
		"The %s transaction anchors exactly the certified accumulator Merkle root.", network)
	if res.Match == anchor.MatchContained {
		message = fmt.Sprintf(
			"The %s transaction anchors a payload that embeds the certified accumulator Merkle root.",
			network)
	}

	if note := blockMismatchNote(a, res); note != "" {
		message += " " + note
	}

	return report.NewValid(id, title, message).WithDetails(details)
}

// anchorErrorCheck maps a provider failure to a check.
//
// A transaction that the network does not know is a failing check: a proof
// referencing a transaction that does not exist is not anchored. A network that
// could not be reached is a skipped check, because nothing was learned either
// way and an unreachable endpoint must never look like a failed proof.
func anchorErrorCheck(id, title, network string, err error, details map[string]string) report.Check {
	details["error"] = err.Error()

	switch {
	case errors.Is(err, anchor.ErrTransactionNotFound):
		return report.NewInvalid(id, title, fmt.Sprintf(
			"The %s network does not know the declared transaction, so the accumulator root is not "+
				"anchored there.", network)).
			WithDetails(details)
	case errors.Is(err, anchor.ErrNoPayload):
		return report.NewInvalid(id, title, fmt.Sprintf(
			"The %s transaction exists but carries no anchored payload at all.", network)).
			WithDetails(details)
	default:
		return report.NewSkipped(id, title, fmt.Sprintf(
			"The anchored payload could not be read from the %s network: %s. Nothing is implied "+
				"about the anchor itself.", network, err)).
			WithDetails(details)
	}
}

// blockMismatchNote reports a disagreement between the block the manifest
// records and the one the network reports.
//
// It is contextual information only: the anchoring evidence is the payload, and
// the manifest block reference is metadata that may legitimately be stale or
// unset.
func blockMismatchNote(a proof.Anchor, res *anchor.Result) string {
	if a.BlockNumber == 0 || res.BlockNumber == 0 || a.BlockNumber == res.BlockNumber {
		return ""
	}

	return fmt.Sprintf(
		"Note: the manifest records block %d while the network reports block %d for this transaction.",
		a.BlockNumber, res.BlockNumber)
}

func anchorCheckID(a proof.Anchor) string {
	network := strings.ToLower(strings.TrimSpace(a.ProviderName))
	if network == "" {
		network = "unknown"
	}

	return "anchors." + network
}

func anchorTitle(a proof.Anchor) string {
	name := strings.TrimSpace(a.ProviderName)
	if name == "" {
		return "Unknown network"
	}

	return strings.ToUpper(name[:1]) + name[1:]
}

func sortedNetworks(r anchor.Registry) []string {
	networks := r.Networks()
	sort.Strings(networks)

	return networks
}

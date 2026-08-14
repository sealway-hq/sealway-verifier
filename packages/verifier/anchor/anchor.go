// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

// Package anchor verifies that the accumulator Merkle root is present in the
// public blockchain transactions referenced by a proof.
//
// A transaction existing is not evidence of anything. What is verified is the
// payload actually carried on chain: the anchored data must encode the expected
// accumulator root according to the public anchoring format.
//
// Providers are independent implementations behind a single interface, reach
// only unauthenticated public endpoints, and take their HTTP client by
// injection so that the same code runs from a command line tool, from a desktop
// application and from a browser WebAssembly build.
package anchor

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// DefaultTimeout bounds a single anchor lookup.
const DefaultTimeout = 15 * time.Second

// Anchor references one public blockchain transaction declared by a proof.
type Anchor struct {
	// Network is the lowercase public network name, such as "algorand",
	// "polygon" or "base".
	Network string
	// TransactionID identifies the transaction on that network.
	TransactionID string
	// BlockNumber is the block or round the issuer recorded, zero when unknown.
	BlockNumber uint64
	// BlockHash is the block hash the issuer recorded, empty when unknown.
	BlockHash string
}

// Match describes how the expected root was found in the anchored payload.
type Match string

const (
	// MatchExact means the anchored payload is exactly the expected root.
	MatchExact Match = "exact"
	// MatchContained means the anchored payload embeds the expected root, which
	// a future anchoring format may legitimately do by adding a envelope around
	// it.
	MatchContained Match = "contained"
	// MatchNone means the expected root is absent from the anchored payload.
	MatchNone Match = "none"
)

// Result is the outcome of one anchor lookup.
type Result struct {
	// Verified reports whether the anchored payload carries the expected root.
	Verified bool
	// Match describes how the root was found.
	Match Match
	// Payload is the raw payload read from the transaction.
	Payload []byte
	// BlockNumber is the block or round reported by the network, zero when the
	// endpoint does not expose it.
	BlockNumber uint64
	// BlockHash is the block hash reported by the network, empty when the
	// endpoint does not expose it.
	BlockHash string
	// Endpoint is the public endpoint that answered, recorded so that a report
	// states where its evidence came from.
	Endpoint string
}

// Errors a provider returns for conditions the caller reports differently.
var (
	// ErrTransactionNotFound is returned when the network does not know the
	// referenced transaction. It makes the anchor check fail rather than skip:
	// a proof referencing a transaction that does not exist is not anchored.
	ErrTransactionNotFound = errors.New("anchor: the transaction was not found")
	// ErrNoPayload is returned when the transaction exists but carries no
	// anchored payload at all.
	ErrNoPayload = errors.New("anchor: the transaction carries no anchored payload")
	// ErrUnsupportedNetwork is returned by a registry for a network with no
	// configured provider.
	ErrUnsupportedNetwork = errors.New("anchor: no verifier is configured for this network")
)

// Verifier verifies the anchors of one public network.
//
// Implementations must be safe for concurrent use and must respect the deadline
// carried by the context.
type Verifier interface {
	// Network returns the lowercase network name this verifier handles.
	Network() string
	// Endpoint returns the public endpoint the verifier queries, for reporting.
	Endpoint() string
	// Verify looks the transaction up and reports whether its anchored payload
	// carries the expected accumulator root.
	//
	// A transport or decoding failure is returned as an error; a transaction
	// that exists but does not carry the expected root is returned as a Result
	// with Verified set to false.
	Verify(ctx context.Context, a Anchor, expectedRoot []byte) (*Result, error)
}

// Registry resolves a network name to its verifier.
type Registry map[string]Verifier

// Verifier returns the verifier registered for the network, if any.
func (r Registry) Verifier(network string) (Verifier, bool) {
	v, ok := r[network]

	return v, ok
}

// Networks returns the registered network names.
func (r Registry) Networks() []string {
	out := make([]string, 0, len(r))
	for n := range r {
		out = append(out, n)
	}

	return out
}

// HTTPClient is the subset of net/http used by the providers. Taking it as an
// interface keeps the providers testable without a live network and lets a
// browser build supply its own transport.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Classify reports how the expected root appears in the anchored payload.
func Classify(payload, expectedRoot []byte) Match {
	switch {
	case len(expectedRoot) == 0 || len(payload) == 0:
		return MatchNone
	case equal(payload, expectedRoot):
		return MatchExact
	case contains(payload, expectedRoot):
		return MatchContained
	default:
		return MatchNone
	}
}

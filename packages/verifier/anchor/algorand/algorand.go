// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

// Package algorand verifies Sealway anchors on the Algorand public network.
//
// It queries an unauthenticated public indexer for the referenced transaction
// and inspects its note field, which is where the accumulator Merkle root is
// anchored. No API key is required, so the same verification runs unchanged from
// a browser.
package algorand

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/sealway-hq/sealway-verifier/packages/verifier/anchor"
)

// DefaultEndpoint is the public AlgoNode mainnet indexer, which serves
// unauthenticated requests. It is configurable so that no third party
// infrastructure is baked into the verifier.
const DefaultEndpoint = "https://mainnet-idx.algonode.cloud"

// Network is the network name handled by this provider.
const Network = "algorand"

// maxTxIDLen bounds the base32 transaction identifier accepted from a manifest.
const txIDLen = 52

// Verifier verifies anchors on the Algorand public network.
type Verifier struct {
	endpoint string
	client   anchor.HTTPClient
}

// New returns an Algorand verifier using the default public indexer when no
// endpoint is supplied.
func New(endpoint string, client anchor.HTTPClient) *Verifier {
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}

	return &Verifier{endpoint: strings.TrimRight(endpoint, "/"), client: client}
}

// Network implements anchor.Verifier.
func (v *Verifier) Network() string { return Network }

// Endpoint implements anchor.Verifier.
func (v *Verifier) Endpoint() string { return v.endpoint }

type indexerTransaction struct {
	ID              string `json:"id"`
	Note            string `json:"note"`
	ConfirmedRound  uint64 `json:"confirmed-round"`
	TxType          string `json:"tx-type"`
	RoundTime       int64  `json:"round-time"`
	GenesisHashB64  string `json:"genesis-hash"`
	IntraRoundIndex int    `json:"intra-round-offset"`
}

type indexerResponse struct {
	Transaction *indexerTransaction `json:"transaction"`
	Message     string              `json:"message"`

	// Some deployments answer with the transaction at the top level rather than
	// nested, so the same fields are decoded twice and the nested form wins.
	ID   string `json:"id"`
	Note string `json:"note"`
}

// Verify implements anchor.Verifier.
//
// It reads the transaction note and compares it with the expected accumulator
// root. A transaction that exists but whose note does not carry the root is
// reported as not verified, never as verified.
func (v *Verifier) Verify(ctx context.Context, a anchor.Anchor, expectedRoot []byte) (*anchor.Result, error) {
	txID, err := normalizeTxID(a.TransactionID)
	if err != nil {
		return nil, err
	}

	tx, err := v.getTransaction(ctx, txID)
	if err != nil {
		return nil, err
	}

	if tx.Note == "" {
		return nil, anchor.ErrNoPayload
	}

	payload, err := decodeNote(tx.Note)
	if err != nil {
		return nil, fmt.Errorf("algorand: cannot decode the transaction note: %w", err)
	}

	match := anchor.Classify(payload, expectedRoot)

	return &anchor.Result{
		Verified:    match != anchor.MatchNone,
		Match:       match,
		Payload:     payload,
		BlockNumber: tx.ConfirmedRound,
		Endpoint:    v.endpoint,
	}, nil
}

func (v *Verifier) getTransaction(ctx context.Context, txID string) (*indexerTransaction, error) {
	endpoint := v.endpoint + "/v2/transactions/" + url.PathEscape(txID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("algorand: cannot build the request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", anchor.UserAgent)

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("algorand: %s is unreachable: %w", v.endpoint, err)
	}

	defer func() { _ = resp.Body.Close() }()

	data, err := anchor.ReadBody(resp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, anchor.ErrTransactionNotFound
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("algorand: %s answered with HTTP %d", v.endpoint, resp.StatusCode)
	}

	var out indexerResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("algorand: %s returned a malformed response: %w", v.endpoint, err)
	}

	if out.Transaction != nil {
		return out.Transaction, nil
	}

	if out.ID != "" || out.Note != "" {
		return &indexerTransaction{ID: out.ID, Note: out.Note}, nil
	}

	return nil, anchor.ErrTransactionNotFound
}

// normalizeTxID validates an Algorand transaction identifier.
//
// Only a well formed 52 character base32 identifier is accepted, so that a
// hostile manifest cannot turn it into an arbitrary request path.
func normalizeTxID(id string) (string, error) {
	s := strings.ToUpper(strings.TrimSpace(id))

	if len(s) != txIDLen {
		return "", fmt.Errorf("algorand: %q is not a %d character transaction identifier", id, txIDLen)
	}

	for _, r := range s {
		if (r < 'A' || r > 'Z') && (r < '2' || r > '7') {
			return "", fmt.Errorf("algorand: %q is not a base32 transaction identifier", id)
		}
	}

	return s, nil
}

// decodeNote decodes the base64 note field. Standard and URL safe alphabets are
// both accepted, with and without padding.
func decodeNote(note string) ([]byte, error) {
	note = strings.TrimSpace(note)

	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}

	var lastErr error

	for _, enc := range encodings {
		raw, err := enc.DecodeString(note)
		if err == nil {
			return raw, nil
		}

		lastErr = err
	}

	return nil, lastErr
}

// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

// Package evm verifies Sealway anchors on Ethereum compatible networks such as
// Polygon and Base.
//
// It uses the standard eth_getTransactionByHash JSON-RPC method against an
// ordinary public node, and inspects the transaction input data, which is where
// the accumulator Merkle root is anchored. No block explorer API, no API key and
// no authenticated infrastructure are involved, so the same verification runs
// unchanged from a browser.
package evm

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/sealway-hq/sealway-verifier/packages/verifier/anchor"
)

// Public JSON-RPC endpoints used by default.
//
// They are ordinary unauthenticated public nodes and are configurable, so that
// no third party infrastructure is baked into the verifier.
const (
	DefaultPolygonEndpoint = "https://polygon-bor-rpc.publicnode.com"
	DefaultBaseEndpoint    = "https://base-rpc.publicnode.com"
)

// Network names handled by this provider.
const (
	NetworkPolygon = "polygon"
	NetworkBase    = "base"
)

// Verifier verifies anchors on one Ethereum compatible network.
type Verifier struct {
	network  string
	endpoint string
	client   anchor.HTTPClient
}

// New returns a verifier for the given network and public JSON-RPC endpoint.
func New(network, endpoint string, client anchor.HTTPClient) *Verifier {
	return &Verifier{network: network, endpoint: endpoint, client: client}
}

// NewPolygon returns a Polygon verifier using the default public endpoint when
// none is supplied.
func NewPolygon(endpoint string, client anchor.HTTPClient) *Verifier {
	if endpoint == "" {
		endpoint = DefaultPolygonEndpoint
	}

	return New(NetworkPolygon, endpoint, client)
}

// NewBase returns a Base verifier using the default public endpoint when none is
// supplied.
func NewBase(endpoint string, client anchor.HTTPClient) *Verifier {
	if endpoint == "" {
		endpoint = DefaultBaseEndpoint
	}

	return New(NetworkBase, endpoint, client)
}

// Network implements anchor.Verifier.
func (v *Verifier) Network() string { return v.network }

// Endpoint implements anchor.Verifier.
func (v *Verifier) Endpoint() string { return v.endpoint }

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcTransaction struct {
	Hash        string `json:"hash"`
	Input       string `json:"input"`
	BlockNumber string `json:"blockNumber"`
	BlockHash   string `json:"blockHash"`
	From        string `json:"from"`
	To          string `json:"to"`
}

type rpcResponse struct {
	Error  *rpcError       `json:"error"`
	Result *rpcTransaction `json:"result"`
}

// Verify implements anchor.Verifier.
//
// It reads the transaction input data and compares it with the expected
// accumulator root. A transaction that exists but whose input does not carry the
// root is reported as not verified, never as verified.
func (v *Verifier) Verify(ctx context.Context, a anchor.Anchor, expectedRoot []byte) (*anchor.Result, error) {
	txID, err := normalizeTxHash(a.TransactionID)
	if err != nil {
		return nil, err
	}

	tx, err := v.getTransaction(ctx, txID)
	if err != nil {
		return nil, err
	}

	payload, err := decodeHexData(tx.Input)
	if err != nil {
		return nil, fmt.Errorf("evm: cannot decode the transaction input: %w", err)
	}

	if len(payload) == 0 {
		return nil, anchor.ErrNoPayload
	}

	match := anchor.Classify(payload, expectedRoot)

	return &anchor.Result{
		Verified:    match != anchor.MatchNone,
		Match:       match,
		Payload:     payload,
		BlockNumber: parseQuantity(tx.BlockNumber),
		BlockHash:   tx.BlockHash,
		Endpoint:    v.endpoint,
	}, nil
}

func (v *Verifier) getTransaction(ctx context.Context, txID string) (*rpcTransaction, error) {
	body, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "eth_getTransactionByHash",
		Params:  []any{txID},
	})
	if err != nil {
		return nil, fmt.Errorf("evm: cannot encode the request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("evm: cannot build the request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", anchor.UserAgent)

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("evm: %s is unreachable: %w", v.endpoint, err)
	}

	defer func() { _ = resp.Body.Close() }()

	data, err := anchor.ReadBody(resp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("evm: %s answered with HTTP %d", v.endpoint, resp.StatusCode)
	}

	var out rpcResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("evm: %s returned a malformed response: %w", v.endpoint, err)
	}

	if out.Error != nil {
		return nil, fmt.Errorf("evm: %s returned an error: %s (code %d)",
			v.endpoint, out.Error.Message, out.Error.Code)
	}

	if out.Result == nil {
		return nil, anchor.ErrTransactionNotFound
	}

	return out.Result, nil
}

// normalizeTxHash validates and normalizes a transaction hash.
//
// Only a well formed 32 byte hash is accepted, so that a hostile manifest cannot
// turn a transaction identifier into an arbitrary RPC parameter.
func normalizeTxHash(id string) (string, error) {
	s := strings.TrimSpace(id)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")

	if len(s) != 64 {
		return "", fmt.Errorf("evm: %q is not a 32 byte transaction hash", id)
	}

	if _, err := hex.DecodeString(s); err != nil {
		return "", fmt.Errorf("evm: %q is not a hexadecimal transaction hash", id)
	}

	return "0x" + strings.ToLower(s), nil
}

func decodeHexData(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")

	if s == "" {
		return nil, nil
	}

	if len(s)%2 != 0 {
		return nil, errors.New("odd number of hexadecimal characters")
	}

	return hex.DecodeString(s)
}

// parseQuantity decodes an Ethereum JSON-RPC hexadecimal quantity, returning
// zero when it is absent or malformed. The block number is reporting metadata
// only, never a verification input.
func parseQuantity(s string) uint64 {
	s = strings.TrimPrefix(strings.TrimSpace(s), "0x")
	if s == "" {
		return 0
	}

	n, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return 0
	}

	return n
}

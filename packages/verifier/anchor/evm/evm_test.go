// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package evm_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealway-hq/sealway-verifier/packages/verifier/anchor"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/anchor/evm"
)

// The transaction identifier and payload mirror the shape of a real Sealway
// anchor: the accumulator Merkle root is the whole transaction input.
const txID = "0x937321db55b20eab05656eb1267a353f24fd914b088d446df0d82a32af6646d5"

func root() []byte { return bytes.Repeat([]byte{0xda, 0x0a}, 32) }

func testAnchor() anchor.Anchor {
	return anchor.Anchor{Network: evm.NetworkPolygon, TransactionID: txID, BlockNumber: 91994197}
}

// rpcServer serves a canned eth_getTransactionByHash response and records the
// request it received.
func rpcServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	return srv
}

func resultResponse(input, blockNumber string) string {
	return `{"jsonrpc":"2.0","id":1,"result":{"hash":"` + txID +
		`","input":"` + input + `","blockNumber":"` + blockNumber +
		`","blockHash":"0x987b","from":"0x2cea","to":"0x2cea"}}`
}

func TestVerifyExactMatch(t *testing.T) {
	t.Parallel()

	var captured map[string]any

	srv := rpcServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &captured))

		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, resultResponse("0x"+hex.EncodeToString(root()), "0x57bb855"))
	})

	v := evm.New(evm.NetworkPolygon, srv.URL, srv.Client())
	assert.Equal(t, evm.NetworkPolygon, v.Network())
	assert.Equal(t, srv.URL, v.Endpoint())

	res, err := v.Verify(t.Context(), testAnchor(), root())
	require.NoError(t, err)

	assert.True(t, res.Verified)
	assert.Equal(t, anchor.MatchExact, res.Match)
	assert.Equal(t, root(), res.Payload)
	assert.Equal(t, uint64(91994197), res.BlockNumber)
	assert.Equal(t, srv.URL, res.Endpoint)

	// The standard JSON-RPC method is used, not a block explorer API.
	assert.Equal(t, "eth_getTransactionByHash", captured["method"])
	assert.Equal(t, []any{txID}, captured["params"])
}

func TestVerifyContainedMatch(t *testing.T) {
	t.Parallel()

	payload := append([]byte{0xaa, 0xbb}, root()...)

	srv := rpcServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, resultResponse("0x"+hex.EncodeToString(payload), "0x1"))
	})

	res, err := evm.New(evm.NetworkPolygon, srv.URL, srv.Client()).
		Verify(t.Context(), testAnchor(), root())
	require.NoError(t, err)

	assert.True(t, res.Verified)
	assert.Equal(t, anchor.MatchContained, res.Match)
}

// TestVerifyRejectsWrongRoot is the property that matters: a transaction that
// exists is not evidence unless its payload carries the expected root.
func TestVerifyRejectsWrongRoot(t *testing.T) {
	t.Parallel()

	other := bytes.Repeat([]byte{0x99}, 64)

	srv := rpcServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, resultResponse("0x"+hex.EncodeToString(other), "0x1"))
	})

	res, err := evm.New(evm.NetworkPolygon, srv.URL, srv.Client()).
		Verify(t.Context(), testAnchor(), root())
	require.NoError(t, err)

	assert.False(t, res.Verified)
	assert.Equal(t, anchor.MatchNone, res.Match)
	assert.Equal(t, other, res.Payload)
}

func TestVerifyMissingTransaction(t *testing.T) {
	t.Parallel()

	srv := rpcServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":null}`)
	})

	_, err := evm.New(evm.NetworkPolygon, srv.URL, srv.Client()).
		Verify(t.Context(), testAnchor(), root())
	assert.ErrorIs(t, err, anchor.ErrTransactionNotFound)
}

func TestVerifyEmptyInput(t *testing.T) {
	t.Parallel()

	srv := rpcServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, resultResponse("0x", "0x1"))
	})

	_, err := evm.New(evm.NetworkPolygon, srv.URL, srv.Client()).
		Verify(t.Context(), testAnchor(), root())
	assert.ErrorIs(t, err, anchor.ErrNoPayload)
}

func TestVerifyRPCError(t *testing.T) {
	t.Parallel()

	srv := rpcServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32051,"message":"API key disabled"}}`)
	})

	_, err := evm.New(evm.NetworkPolygon, srv.URL, srv.Client()).
		Verify(t.Context(), testAnchor(), root())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API key disabled")
}

func TestVerifyHTTPFailure(t *testing.T) {
	t.Parallel()

	srv := rpcServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	_, err := evm.New(evm.NetworkPolygon, srv.URL, srv.Client()).
		Verify(t.Context(), testAnchor(), root())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "503")
}

func TestVerifyMalformedResponse(t *testing.T) {
	t.Parallel()

	for name, body := range map[string]string{
		"not json":      "<html>gateway error</html>",
		"truncated":     `{"jsonrpc":"2.0","result":{`,
		"odd hex input": `{"jsonrpc":"2.0","result":{"input":"0xabc"}}`,
		"invalid hex":   `{"jsonrpc":"2.0","result":{"input":"0xzzzz"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := rpcServer(t, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, body)
			})

			_, err := evm.New(evm.NetworkPolygon, srv.URL, srv.Client()).
				Verify(t.Context(), testAnchor(), root())
			assert.Error(t, err)
		})
	}
}

func TestVerifyTimeout(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})

	srv := rpcServer(t, func(w http.ResponseWriter, _ *http.Request) {
		<-release

		_, _ = io.WriteString(w, resultResponse("0x", "0x1"))
	})

	t.Cleanup(func() { close(release) })

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	_, err := evm.New(evm.NetworkPolygon, srv.URL, srv.Client()).
		Verify(ctx, testAnchor(), root())
	assert.Error(t, err)
}

func TestVerifyUnreachableEndpoint(t *testing.T) {
	t.Parallel()

	v := evm.New(evm.NetworkPolygon, "http://127.0.0.1:1", &http.Client{Timeout: time.Second})

	_, err := v.Verify(t.Context(), testAnchor(), root())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unreachable")
}

// TestVerifyRejectsMalformedTransactionID checks that a hostile manifest cannot
// turn a transaction identifier into an arbitrary RPC parameter.
func TestVerifyRejectsMalformedTransactionID(t *testing.T) {
	t.Parallel()

	called := false

	srv := rpcServer(t, func(w http.ResponseWriter, _ *http.Request) {
		called = true
		_, _ = io.WriteString(w, resultResponse("0x", "0x1"))
	})

	for name, id := range map[string]string{
		"empty":        "",
		"too short":    "0xdeadbeef",
		"too long":     "0x" + hex.EncodeToString(bytes.Repeat([]byte{0x01}, 40)),
		"not hex":      "0x" + string(bytes.Repeat([]byte("z"), 64)),
		"injection":    "0x../../admin",
		"with newline": "0x937321db55b20eab05656eb1267a353f24fd914b088d446df0d82a32af6646d5\nX",
	} {
		t.Run(name, func(t *testing.T) {
			a := testAnchor()
			a.TransactionID = id

			_, err := evm.New(evm.NetworkPolygon, srv.URL, srv.Client()).
				Verify(t.Context(), a, root())
			assert.Error(t, err)
		})
	}

	assert.False(t, called, "a malformed identifier must never reach the network")
}

func TestVerifyNormalizesTransactionID(t *testing.T) {
	t.Parallel()

	var captured map[string]any

	srv := rpcServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		_, _ = io.WriteString(w, resultResponse("0x"+hex.EncodeToString(root()), "0x1"))
	})

	a := testAnchor()
	a.TransactionID = "  937321DB55B20EAB05656EB1267A353F24FD914B088D446DF0D82A32AF6646D5  "

	_, err := evm.New(evm.NetworkPolygon, srv.URL, srv.Client()).Verify(t.Context(), a, root())
	require.NoError(t, err)
	assert.Equal(t, []any{txID}, captured["params"])
}

func TestDefaultEndpoints(t *testing.T) {
	t.Parallel()

	assert.Equal(t, evm.DefaultPolygonEndpoint, evm.NewPolygon("", nil).Endpoint())
	assert.Equal(t, evm.DefaultBaseEndpoint, evm.NewBase("", nil).Endpoint())
	assert.Equal(t, evm.NetworkPolygon, evm.NewPolygon("", nil).Network())
	assert.Equal(t, evm.NetworkBase, evm.NewBase("", nil).Network())
	assert.Equal(t, "https://example.test", evm.NewBase("https://example.test", nil).Endpoint())
}

func TestVerifyRejectsOversizedResponse(t *testing.T) {
	t.Parallel()

	srv := rpcServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("A"), anchor.MaxResponseSize+10))
	})

	_, err := evm.New(evm.NetworkPolygon, srv.URL, srv.Client()).
		Verify(t.Context(), testAnchor(), root())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds")
}

// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package algorand_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealway-hq/sealway-verifier/packages/verifier/anchor"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/anchor/algorand"
)

// The transaction identifier mirrors the shape of a real Sealway anchor: the
// accumulator Merkle root is the raw content of the note field.
const txID = "3DZT62LVBKVIYULEPC3QGNEWVMKZEBHXA2PX7BBYU4TL7ZZI2EQQ"

func root() []byte { return bytes.Repeat([]byte{0xda, 0x0a}, 32) }

func testAnchor() anchor.Anchor {
	return anchor.Anchor{Network: algorand.Network, TransactionID: txID, BlockNumber: 64055209}
}

func indexer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	return srv
}

func nested(note string, round uint64) string {
	return `{"current-round":1,"transaction":{"id":"` + txID +
		`","note":"` + note + `","tx-type":"pay","confirmed-round":` + itoa(round) + `}}`
}

func itoa(n uint64) string {
	if n == 0 {
		return "0"
	}

	var buf []byte
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}

	return string(buf)
}

func TestVerifyExactMatch(t *testing.T) {
	t.Parallel()

	var path string

	srv := indexer(t, func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path

		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, nested(base64.StdEncoding.EncodeToString(root()), 64055209))
	})

	v := algorand.New(srv.URL, srv.Client())
	assert.Equal(t, algorand.Network, v.Network())
	assert.Equal(t, srv.URL, v.Endpoint())

	res, err := v.Verify(t.Context(), testAnchor(), root())
	require.NoError(t, err)

	assert.True(t, res.Verified)
	assert.Equal(t, anchor.MatchExact, res.Match)
	assert.Equal(t, root(), res.Payload)
	assert.Equal(t, uint64(64055209), res.BlockNumber)
	assert.Equal(t, "/v2/transactions/"+txID, path)
}

func TestVerifyAcceptsFlatResponse(t *testing.T) {
	t.Parallel()

	srv := indexer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"id":"`+txID+`","note":"`+
			base64.StdEncoding.EncodeToString(root())+`"}`)
	})

	res, err := algorand.New(srv.URL, srv.Client()).Verify(t.Context(), testAnchor(), root())
	require.NoError(t, err)
	assert.True(t, res.Verified)
}

func TestVerifyAcceptsUnpaddedAndURLSafeBase64(t *testing.T) {
	t.Parallel()

	payload := append(root(), 0xfb, 0xff)

	for name, encoded := range map[string]string{
		"raw std": base64.RawStdEncoding.EncodeToString(payload),
		"url":     base64.URLEncoding.EncodeToString(payload),
		"raw url": base64.RawURLEncoding.EncodeToString(payload),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := indexer(t, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, nested(encoded, 1))
			})

			res, err := algorand.New(srv.URL, srv.Client()).Verify(t.Context(), testAnchor(), root())
			require.NoError(t, err)
			assert.True(t, res.Verified)
			assert.Equal(t, anchor.MatchContained, res.Match)
		})
	}
}

// TestVerifyRejectsWrongRoot is the property that matters: a transaction that
// exists is not evidence unless its note carries the expected root.
func TestVerifyRejectsWrongRoot(t *testing.T) {
	t.Parallel()

	other := bytes.Repeat([]byte{0x99}, 64)

	srv := indexer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, nested(base64.StdEncoding.EncodeToString(other), 1))
	})

	res, err := algorand.New(srv.URL, srv.Client()).Verify(t.Context(), testAnchor(), root())
	require.NoError(t, err)

	assert.False(t, res.Verified)
	assert.Equal(t, anchor.MatchNone, res.Match)
}

func TestVerifyMissingTransaction(t *testing.T) {
	t.Parallel()

	srv := indexer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"message":"no transaction found"}`)
	})

	_, err := algorand.New(srv.URL, srv.Client()).Verify(t.Context(), testAnchor(), root())
	assert.ErrorIs(t, err, anchor.ErrTransactionNotFound)
}

func TestVerifyEmptyBody(t *testing.T) {
	t.Parallel()

	srv := indexer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{}`)
	})

	_, err := algorand.New(srv.URL, srv.Client()).Verify(t.Context(), testAnchor(), root())
	assert.ErrorIs(t, err, anchor.ErrTransactionNotFound)
}

func TestVerifyTransactionWithoutNote(t *testing.T) {
	t.Parallel()

	srv := indexer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, nested("", 1))
	})

	_, err := algorand.New(srv.URL, srv.Client()).Verify(t.Context(), testAnchor(), root())
	assert.ErrorIs(t, err, anchor.ErrNoPayload)
}

func TestVerifyMalformedResponse(t *testing.T) {
	t.Parallel()

	for name, body := range map[string]string{
		"not json":      "<html>gateway error</html>",
		"truncated":     `{"transaction":{`,
		"note not b64":  nested("!!!! not base64 !!!!", 1),
		"note is array": `{"transaction":{"note":[1,2,3]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := indexer(t, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, body)
			})

			_, err := algorand.New(srv.URL, srv.Client()).Verify(t.Context(), testAnchor(), root())
			assert.Error(t, err)
		})
	}
}

func TestVerifyHTTPFailure(t *testing.T) {
	t.Parallel()

	srv := indexer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})

	_, err := algorand.New(srv.URL, srv.Client()).Verify(t.Context(), testAnchor(), root())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "502")
}

func TestVerifyTimeout(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})

	srv := indexer(t, func(w http.ResponseWriter, _ *http.Request) {
		<-release
	})

	t.Cleanup(func() { close(release) })

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	_, err := algorand.New(srv.URL, srv.Client()).Verify(ctx, testAnchor(), root())
	assert.Error(t, err)
}

func TestVerifyUnreachableEndpoint(t *testing.T) {
	t.Parallel()

	v := algorand.New("http://127.0.0.1:1", &http.Client{Timeout: time.Second})

	_, err := v.Verify(t.Context(), testAnchor(), root())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unreachable")
}

// TestVerifyRejectsMalformedTransactionID checks that a hostile manifest cannot
// turn a transaction identifier into an arbitrary request path.
func TestVerifyRejectsMalformedTransactionID(t *testing.T) {
	t.Parallel()

	called := false

	srv := indexer(t, func(w http.ResponseWriter, _ *http.Request) {
		called = true
	})

	for name, id := range map[string]string{
		"empty":           "",
		"too short":       "ABC",
		"too long":        txID + "EXTRA",
		"path traversal":  "../../../../etc/passwd/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"invalid base32":  "3DZT62LVBKVIYULEPC3QGNEWVMKZEBHXA2PX7BBYU4TL7ZZI2E01",
		"query injection": "3DZT62LVBKVIYULEPC3QGNEWVMKZEBHXA2PX7BBYU4TL7ZZ?x=1",
	} {
		t.Run(name, func(t *testing.T) {
			a := testAnchor()
			a.TransactionID = id

			_, err := algorand.New(srv.URL, srv.Client()).Verify(t.Context(), a, root())
			assert.Error(t, err)
		})
	}

	assert.False(t, called, "a malformed identifier must never reach the network")
}

func TestDefaultEndpoint(t *testing.T) {
	t.Parallel()

	assert.Equal(t, algorand.DefaultEndpoint, algorand.New("", nil).Endpoint())
	assert.Equal(t, "https://example.test", algorand.New("https://example.test/", nil).Endpoint())
}

func TestVerifyRejectsOversizedResponse(t *testing.T) {
	t.Parallel()

	srv := indexer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("A"), anchor.MaxResponseSize+10))
	})

	_, err := algorand.New(srv.URL, srv.Client()).Verify(t.Context(), testAnchor(), root())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds")
}

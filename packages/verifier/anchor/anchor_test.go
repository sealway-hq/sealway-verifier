// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package anchor_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealway-hq/sealway-verifier/packages/verifier/anchor"
)

type stubVerifier struct{ network string }

func (s stubVerifier) Network() string  { return s.network }
func (s stubVerifier) Endpoint() string { return "https://stub.test" }

func (s stubVerifier) Verify(context.Context, anchor.Anchor, []byte) (*anchor.Result, error) {
	return &anchor.Result{Verified: true, Match: anchor.MatchExact}, nil
}

func TestRegistry(t *testing.T) {
	t.Parallel()

	r := anchor.Registry{
		"algorand": stubVerifier{network: "algorand"},
		"polygon":  stubVerifier{network: "polygon"},
	}

	v, ok := r.Verifier("algorand")
	require.True(t, ok)
	assert.Equal(t, "algorand", v.Network())

	_, ok = r.Verifier("bitcoin")
	assert.False(t, ok)

	networks := r.Networks()
	sort.Strings(networks)
	assert.Equal(t, []string{"algorand", "polygon"}, networks)
}

func TestClassify(t *testing.T) {
	t.Parallel()

	root := bytes.Repeat([]byte{0xab}, 64)

	assert.Equal(t, anchor.MatchExact, anchor.Classify(root, root))
	assert.Equal(t, anchor.MatchContained, anchor.Classify(append([]byte{0x01}, root...), root))
	assert.Equal(t, anchor.MatchContained, anchor.Classify(append(bytes.Clone(root), 0x01), root))
	assert.Equal(t, anchor.MatchNone, anchor.Classify(bytes.Repeat([]byte{0x01}, 64), root))
	assert.Equal(t, anchor.MatchNone, anchor.Classify(nil, root))
	assert.Equal(t, anchor.MatchNone, anchor.Classify(root, nil))

	// A truncated root must never be accepted as a match.
	assert.Equal(t, anchor.MatchNone, anchor.Classify(root[:32], root))
}

func TestReadBodyEnforcesLimit(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("A"), 16))
	}))
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Get(srv.URL)
	require.NoError(t, err)

	defer func() { _ = resp.Body.Close() }()

	body, err := anchor.ReadBody(resp)
	require.NoError(t, err)
	assert.Len(t, body, 16)
}

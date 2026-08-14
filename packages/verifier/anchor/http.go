// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package anchor

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
)

// MaxResponseSize bounds the body read from a public endpoint. Public indexers
// and RPC nodes are untrusted for the purposes of this verifier: a hostile or
// misbehaving endpoint must not be able to exhaust memory.
const MaxResponseSize = 4 << 20 // 4 MiB

// UserAgent identifies the verifier to public endpoints.
const UserAgent = "sealway-verifier"

// ReadBody reads a bounded response body.
//
// Closing the body remains the caller's responsibility, so that the close is
// visible at the call site.
func ReadBody(resp *http.Response) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("anchor: cannot read the response: %w", err)
	}

	if len(data) > MaxResponseSize {
		return nil, fmt.Errorf("anchor: the response exceeds %d bytes", MaxResponseSize)
	}

	return data, nil
}

func equal(a, b []byte) bool { return bytes.Equal(a, b) }

func contains(haystack, needle []byte) bool { return bytes.Contains(haystack, needle) }

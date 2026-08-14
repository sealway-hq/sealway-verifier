// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package proof

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// SHA512Size is the length in bytes of a SHA-512 digest.
const SHA512Size = 64

// maxHashHexLen bounds the hexadecimal input accepted for a single digest. It
// protects the parser against absurdly long strings in a hostile manifest.
const maxHashHexLen = 512

var errHashNotString = errors.New("hash must be a JSON string")

// Hash is a raw digest carried in the manifest as a hexadecimal string.
//
// It always holds the decoded bytes, never the textual form, so that callers
// cannot accidentally hash the ASCII representation of a digest instead of the
// digest itself.
type Hash []byte

// UnmarshalJSON decodes a hexadecimal digest.
//
// Malformed values are rejected rather than repaired: an odd number of digits,
// a non hexadecimal character or a non string JSON value all produce an error.
func (h *Hash) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return errHashNotString
	}

	if s == "" {
		*h = nil

		return nil
	}

	if len(s) > maxHashHexLen {
		return fmt.Errorf("hash is too long: %d hexadecimal characters", len(s))
	}

	raw, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("hash is not valid hexadecimal: %w", err)
	}

	*h = raw

	return nil
}

// MarshalJSON encodes the digest as a lowercase hexadecimal string.
func (h Hash) MarshalJSON() ([]byte, error) {
	return json.Marshal(h.String())
}

// String returns the lowercase hexadecimal representation of the digest.
func (h Hash) String() string {
	return hex.EncodeToString(h)
}

// Bytes returns the raw digest bytes.
func (h Hash) Bytes() []byte { return h }

// IsZero reports whether the digest is absent.
func (h Hash) IsZero() bool { return len(h) == 0 }

// Equal reports whether two digests are identical, in constant time.
func (h Hash) Equal(other Hash) bool {
	if len(h) != len(other) {
		return false
	}

	return subtle.ConstantTimeCompare(h, other) == 1
}

// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package proof_test

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealway-hq/sealway-verifier/packages/verifier/proof"
)

func hex64(b byte) string { return strings.Repeat(hex.EncodeToString([]byte{b}), proof.SHA512Size) }

// validManifest returns a minimal manifest that passes validation. Tests mutate
// one field at a time so each assertion isolates a single rule.
func validManifest(mutate func(m map[string]any)) []byte {
	root := hex64(0x11)
	leaf := hex64(0x22)
	acc := hex64(0x33)

	m := map[string]any{
		"version": "1.1",
		"proof": map[string]any{
			"public_id":      "SW-2026-TEST0001",
			"hash_algorithm": "SHA-512",
			"merkle_root":    root,
			"item_count":     1,
		},
		"items": []any{
			map[string]any{
				"position":    0,
				"filename":    "a.bin",
				"size_bytes":  10,
				"hash_sha512": leaf,
				"leaf_hash":   leaf,
				"merkle_proof": map[string]any{
					"leaf_index":     0,
					"hash_algorithm": "SHA512",
					"siblings": []any{
						map[string]any{"position": "right", "hash": leaf},
					},
				},
			},
		},
		"notarization": map[string]any{
			"algorithm":        "SHA-512",
			"hash":             root,
			"merkle_root":      root,
			"accumulator_root": acc,
			"inclusion_proof": map[string]any{
				"leaf_index":     0,
				"hash_algorithm": "SHA512",
				"siblings": []any{
					map[string]any{"position": "right", "hash": root},
				},
			},
			"blockchain_anchors": []any{
				map[string]any{"provider_name": "algorand", "transaction_id": "TX"},
			},
		},
	}

	if mutate != nil {
		mutate(m)
	}

	out, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}

	return out
}

func TestParseValidManifest(t *testing.T) {
	t.Parallel()

	m, err := proof.ParseBytes(validManifest(nil))
	require.NoError(t, err)
	require.NoError(t, m.Validate())

	assert.Equal(t, "1.1", m.Version)
	assert.Equal(t, "SW-2026-TEST0001", m.Proof.PublicID)
	assert.Len(t, m.Items, 1)
	assert.Len(t, m.Anchors(), 1)

	major, err := m.MajorVersion()
	require.NoError(t, err)
	assert.Equal(t, 1, major)
}

// TestParseIgnoresLegacyFields checks the manifest stays forward and backward
// compatible: fields left over from an older format, and fields added by a newer
// one, are both simply ignored rather than rejected or acted upon.
func TestParseIgnoresLegacyFields(t *testing.T) {
	t.Parallel()

	data := validManifest(func(m map[string]any) {
		items := m["items"].([]any)
		items[0].(map[string]any)["hash_sha256"] = strings.Repeat("ab", 32)
		m["verification"] = map[string]any{
			"instructions": "Compute the SHA-256 hash of each original file",
		}
		m["some_future_field"] = []any{1, 2, 3}
	})

	m, err := proof.ParseBytes(data)
	require.NoError(t, err)
	assert.NoError(t, m.Validate())
}

func TestParseRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"empty":              "",
		"whitespace":         "   \n\t ",
		"not json":           "this is not json",
		"truncated":          `{"version": "1.1"`,
		"array":              `["not", "an", "object"]`,
		"trailing document":  `{"version":"1.1"}{"version":"1.1"}`,
		"hash not a string":  `{"proof":{"merkle_root":12345}}`,
		"hash not hex":       `{"proof":{"merkle_root":"zzzz"}}`,
		"hash odd length":    `{"proof":{"merkle_root":"abc"}}`,
		"hash absurdly long": `{"proof":{"merkle_root":"` + strings.Repeat("ab", 400) + `"}}`,
	}

	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := proof.ParseBytes([]byte(input))
			assert.Error(t, err)
		})
	}
}

func TestParseEnforcesSizeLimit(t *testing.T) {
	t.Parallel()

	data := validManifest(nil)

	_, err := proof.Parse(strings.NewReader(string(data)), int64(len(data)))
	require.NoError(t, err)

	_, err = proof.Parse(strings.NewReader(string(data)), int64(len(data))-1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "maximum accepted size")
}

func TestValidateRejects(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		mutate func(m map[string]any)
		want   string
	}{
		{
			name:   "missing version",
			mutate: func(m map[string]any) { delete(m, "version") },
			want:   "version is missing",
		},
		{
			name:   "unsupported major version",
			mutate: func(m map[string]any) { m["version"] = "2.0" },
			want:   "unsupported schema major version 2",
		},
		{
			name:   "unparsable version",
			mutate: func(m map[string]any) { m["version"] = "not-a-version" },
			want:   "not a valid schema version",
		},
		{
			name: "missing public id",
			mutate: func(m map[string]any) {
				delete(m["proof"].(map[string]any), "public_id")
			},
			want: "proof.public_id: is required",
		},
		{
			name: "wrong hash algorithm",
			mutate: func(m map[string]any) {
				m["proof"].(map[string]any)["hash_algorithm"] = "SHA-256"
			},
			want: "unsupported hash algorithm",
		},
		{
			name: "missing merkle root",
			mutate: func(m map[string]any) {
				delete(m["proof"].(map[string]any), "merkle_root")
			},
			want: "proof.merkle_root: is required",
		},
		{
			name: "short merkle root",
			mutate: func(m map[string]any) {
				m["proof"].(map[string]any)["merkle_root"] = strings.Repeat("ab", 32)
			},
			want: "must be a SHA-512 digest of 64 bytes",
		},
		{
			name: "item count disagrees",
			mutate: func(m map[string]any) {
				m["proof"].(map[string]any)["item_count"] = 7
			},
			want: "declares 7 items but the manifest carries 1",
		},
		{
			name:   "no items",
			mutate: func(m map[string]any) { m["items"] = []any{}; m["proof"].(map[string]any)["item_count"] = 0 },
			want:   "at least one certified item is required",
		},
		{
			name: "duplicate position",
			mutate: func(m map[string]any) {
				items := m["items"].([]any)

				clone := map[string]any{}
				for k, v := range items[0].(map[string]any) {
					clone[k] = v
				}

				m["items"] = []any{items[0], clone}
				m["proof"].(map[string]any)["item_count"] = 2
			},
			want: "duplicates the position",
		},
		{
			name: "non contiguous positions",
			mutate: func(m map[string]any) {
				m["items"].([]any)[0].(map[string]any)["position"] = 5
				m["items"].([]any)[0].(map[string]any)["merkle_proof"].(map[string]any)["leaf_index"] = 0
			},
			want: "contiguous range",
		},
		{
			name: "negative size",
			mutate: func(m map[string]any) {
				m["items"].([]any)[0].(map[string]any)["size_bytes"] = -1
			},
			want: "size_bytes: must not be negative",
		},
		{
			name: "leaf hash disagrees with sha512",
			mutate: func(m map[string]any) {
				m["items"].([]any)[0].(map[string]any)["leaf_hash"] = hex64(0x44)
			},
			want: "does not match hash_sha512",
		},
		{
			name: "invalid leaf hash length",
			mutate: func(m map[string]any) {
				m["items"].([]any)[0].(map[string]any)["leaf_hash"] = strings.Repeat("ab", 10)
			},
			want: "must be a SHA-512 digest",
		},
		{
			name: "leaf index out of range",
			mutate: func(m map[string]any) {
				m["items"].([]any)[0].(map[string]any)["merkle_proof"].(map[string]any)["leaf_index"] = 9
			},
			want: "out of range",
		},
		{
			name: "invalid sibling direction",
			mutate: func(m map[string]any) {
				p := m["items"].([]any)[0].(map[string]any)["merkle_proof"].(map[string]any)
				p["siblings"].([]any)[0].(map[string]any)["position"] = "sideways"
			},
			want: "invalid sibling direction",
		},
		{
			name: "empty inclusion path",
			mutate: func(m map[string]any) {
				p := m["items"].([]any)[0].(map[string]any)["merkle_proof"].(map[string]any)
				p["siblings"] = []any{}
			},
			want: "at least one sibling",
		},
		{
			name: "inclusion path too deep",
			mutate: func(m map[string]any) {
				p := m["items"].([]any)[0].(map[string]any)["merkle_proof"].(map[string]any)

				siblings := make([]any, 0, proof.MaxSiblings+1)
				for range proof.MaxSiblings + 1 {
					siblings = append(siblings, map[string]any{"position": "right", "hash": hex64(0x22)})
				}

				p["siblings"] = siblings
			},
			want: "exceeds the maximum",
		},
		{
			name: "notarization root contradicts proof root",
			mutate: func(m map[string]any) {
				m["notarization"].(map[string]any)["merkle_root"] = hex64(0x55)
			},
			want: "contradicts proof.merkle_root",
		},
		{
			name: "notarized hash contradicts proof root",
			mutate: func(m map[string]any) {
				m["notarization"].(map[string]any)["hash"] = hex64(0x55)
			},
			want: "notarization.hash: contradicts proof.merkle_root",
		},
		{
			name: "missing accumulator root",
			mutate: func(m map[string]any) {
				delete(m["notarization"].(map[string]any), "accumulator_root")
			},
			want: "notarization.accumulator_root: is required",
		},
		{
			name: "anchor without transaction",
			mutate: func(m map[string]any) {
				anchors := m["notarization"].(map[string]any)["blockchain_anchors"].([]any)
				delete(anchors[0].(map[string]any), "transaction_id")
			},
			want: "transaction_id: is required",
		},
		{
			name: "anchor without provider",
			mutate: func(m map[string]any) {
				anchors := m["notarization"].(map[string]any)["blockchain_anchors"].([]any)
				delete(anchors[0].(map[string]any), "provider_name")
			},
			want: "provider_name: is required",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m, err := proof.ParseBytes(validManifest(tc.mutate))
			require.NoError(t, err)

			err = m.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)

			var verr *proof.ValidationError
			require.ErrorAs(t, err, &verr)
			assert.NotEmpty(t, verr.Issues)
		})
	}
}

func TestValidateAcceptsAlternateAlgorithmSpelling(t *testing.T) {
	t.Parallel()

	for _, spelling := range []string{"SHA-512", "SHA512", "sha-512", " sha512 "} {
		data := validManifest(func(m map[string]any) {
			m["proof"].(map[string]any)["hash_algorithm"] = spelling
		})

		m, err := proof.ParseBytes(data)
		require.NoError(t, err)
		assert.NoError(t, m.Validate(), spelling)
	}
}

// TestValidateAcceptsMissingIndividualProof records that an item without an
// inclusion path is not a structural error: the verifier reports it as a skipped
// check instead.
func TestValidateAcceptsMissingIndividualProof(t *testing.T) {
	t.Parallel()

	data := validManifest(func(m map[string]any) {
		delete(m["items"].([]any)[0].(map[string]any), "merkle_proof")
	})

	m, err := proof.ParseBytes(data)
	require.NoError(t, err)
	assert.NoError(t, m.Validate())
	assert.Nil(t, m.Items[0].MerkleProof)
}

func TestValidateReportsEveryIssueAtOnce(t *testing.T) {
	t.Parallel()

	data := validManifest(func(m map[string]any) {
		m["version"] = "9.0"
		delete(m["proof"].(map[string]any), "public_id")
		m["proof"].(map[string]any)["item_count"] = 99
	})

	m, err := proof.ParseBytes(data)
	require.NoError(t, err)

	err = m.Validate()
	require.Error(t, err)

	var verr *proof.ValidationError
	require.ErrorAs(t, err, &verr)
	assert.GreaterOrEqual(t, len(verr.Issues), 3)
}

func TestItemsByPositionSortsAndCopies(t *testing.T) {
	t.Parallel()

	data := validManifest(func(m map[string]any) {
		leaf0, leaf1 := hex64(0x22), hex64(0x66)
		m["items"] = []any{
			map[string]any{"position": 1, "leaf_hash": leaf1, "hash_sha512": leaf1, "filename": "b"},
			map[string]any{"position": 0, "leaf_hash": leaf0, "hash_sha512": leaf0, "filename": "a"},
		}
		m["proof"].(map[string]any)["item_count"] = 2
	})

	m, err := proof.ParseBytes(data)
	require.NoError(t, err)
	require.NoError(t, m.Validate())

	sorted := m.ItemsByPosition()
	require.Len(t, sorted, 2)
	assert.Equal(t, "a", sorted[0].Filename)
	assert.Equal(t, "b", sorted[1].Filename)

	// The manifest itself is left untouched.
	assert.Equal(t, "b", m.Items[0].Filename)

	leaves := m.Leaves()
	require.Len(t, leaves, 2)
	assert.Equal(t, sorted[0].LeafHash.Bytes(), leaves[0])
}

func TestHashJSONRoundTrip(t *testing.T) {
	t.Parallel()

	var h proof.Hash
	require.NoError(t, json.Unmarshal([]byte(`"AABB"`), &h))
	assert.Equal(t, []byte{0xaa, 0xbb}, h.Bytes())
	assert.Equal(t, "aabb", h.String())

	out, err := json.Marshal(h)
	require.NoError(t, err)
	assert.JSONEq(t, `"aabb"`, string(out))
}

func TestHashEmptyIsZero(t *testing.T) {
	t.Parallel()

	var h proof.Hash
	require.NoError(t, json.Unmarshal([]byte(`""`), &h))
	assert.True(t, h.IsZero())
	assert.Equal(t, "", h.String())
}

func TestHashEqual(t *testing.T) {
	t.Parallel()

	a := proof.Hash([]byte{1, 2, 3})
	assert.True(t, a.Equal(proof.Hash([]byte{1, 2, 3})))
	assert.False(t, a.Equal(proof.Hash([]byte{1, 2, 4})))
	assert.False(t, a.Equal(proof.Hash([]byte{1, 2})))
	assert.False(t, a.Equal(nil))
}

func TestIssueString(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "a.b: broken", proof.Issue{Field: "a.b", Message: "broken"}.String())

	var nilErr *proof.ValidationError
	assert.Equal(t, "manifest is invalid", nilErr.Error())
}

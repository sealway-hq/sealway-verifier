// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

// Package proof models and validates the machine readable Sealway proof
// manifest embedded in a certificate.
//
// The manifest is an untrusted external input. Parsing never panics, never
// repairs malformed values and never trusts a declared digest before the
// corresponding verification step has recomputed it.
package proof

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SupportedMajorVersion is the manifest schema major version understood by this
// verifier. A manifest declaring a different major version is rejected. A newer
// minor version is accepted so that additive changes to the public format do
// not break existing verifiers.
const SupportedMajorVersion = 1

// DefaultMaxManifestSize bounds the manifest accepted by Parse.
const DefaultMaxManifestSize = 16 << 20 // 16 MiB

// MaxItems bounds the number of certified items accepted from a manifest.
const MaxItems = 1 << 20

// MaxSiblings bounds the depth of a Merkle inclusion path accepted from a
// manifest. A tree deeper than this cannot be reached with MaxItems leaves.
const MaxSiblings = 64

// SiblingPosition indicates on which side of the current node a sibling sits.
type SiblingPosition string

const (
	// SiblingLeft means the sibling is combined to the left of the current node.
	SiblingLeft SiblingPosition = "left"
	// SiblingRight means the sibling is combined to the right of the current node.
	SiblingRight SiblingPosition = "right"
)

// Manifest is the parsed sealway-proof.json document.
type Manifest struct {
	Version      string       `json:"version"`
	GeneratedAt  time.Time    `json:"generated_at"`
	Partial      bool         `json:"partial"`
	Proof        Proof        `json:"proof"`
	Items        []Item       `json:"items"`
	Notarization Notarization `json:"notarization"`
}

// Proof describes the certified proof as a whole.
type Proof struct {
	ID             string    `json:"id"`
	PublicID       string    `json:"public_id"`
	Category       string    `json:"category"`
	Title          string    `json:"title"`
	HashAlgorithm  string    `json:"hash_algorithm"`
	MerkleRoot     Hash      `json:"merkle_root"`
	ItemCount      int       `json:"item_count"`
	TotalSizeBytes int64     `json:"total_size_bytes"`
	CreatedAt      time.Time `json:"created_at"`
	TimestampedAt  time.Time `json:"timestamped_at"`
}

// Item is one certified file.
//
// The primary proof hash of every item is the SHA-512 of the raw file bytes.
// There is no canonicalization, no content type specific digest and nothing
// derived from the file name, the MIME type or any metadata.
type Item struct {
	Position      int          `json:"position"`
	Kind          string       `json:"kind"`
	Filename      string       `json:"filename"`
	MIMEType      string       `json:"mime_type"`
	SizeBytes     int64        `json:"size_bytes"`
	HashSHA512    Hash         `json:"hash_sha512"`
	LeafHash      Hash         `json:"leaf_hash"`
	SourceStatus  string       `json:"source_status"`
	SourcePresent bool         `json:"source_present"`
	SourceType    string       `json:"source_type"`
	MerkleProof   *MerkleProof `json:"merkle_proof"`
}

// MerkleProof is an inclusion path from a leaf up to a Merkle root.
type MerkleProof struct {
	LeafIndex     int       `json:"leaf_index"`
	HashAlgorithm string    `json:"hash_algorithm"`
	Siblings      []Sibling `json:"siblings"`
}

// Sibling is one step of an inclusion path.
type Sibling struct {
	Position SiblingPosition `json:"position"`
	Hash     Hash            `json:"hash"`
}

// Notarization links the proof Merkle root to the accumulator, to the RFC 3161
// timestamp and to the public blockchain anchors.
type Notarization struct {
	Provider            string          `json:"provider"`
	ExternalID          string          `json:"external_id"`
	Algorithm           string          `json:"algorithm"`
	Hash                Hash            `json:"hash"`
	MerkleRoot          Hash            `json:"merkle_root"`
	AccumulatorRoot     Hash            `json:"accumulator_root"`
	AccumulatorSealedAt time.Time       `json:"accumulator_sealed_at"`
	NotarizedAt         time.Time       `json:"notarized_at"`
	ProofTimestamp      *ProofTimestamp `json:"proof_timestamp"`
	InclusionProof      *MerkleProof    `json:"inclusion_proof"`
	BlockchainAnchors   []Anchor        `json:"blockchain_anchors"`
}

// ProofTimestamp is the metadata the issuer recorded about the RFC 3161 token.
//
// It is informational only. The authoritative values are read from the token
// itself, and the verifier reports any disagreement between the two.
type ProofTimestamp struct {
	TSAProviderName string    `json:"tsa_provider_name"`
	CertSubject     string    `json:"cert_subject"`
	PolicyOID       string    `json:"policy_oid"`
	SerialNumber    string    `json:"serial_number"`
	TimestampedAt   time.Time `json:"timestamped_at"`
}

// Anchor references a public blockchain transaction carrying the accumulator
// Merkle root.
type Anchor struct {
	ProviderName  string    `json:"provider_name"`
	TransactionID string    `json:"transaction_id"`
	BlockNumber   uint64    `json:"block_number"`
	BlockHash     string    `json:"block_hash"`
	Status        string    `json:"status"`
	AnchoredAt    time.Time `json:"anchored_at"`
}

// Parse decodes a manifest from its JSON representation.
//
// Reading is bounded by maxSize; pass zero to use DefaultMaxManifestSize. The
// returned manifest is syntactically well formed but not yet validated: call
// Validate before relying on any of its fields.
func Parse(r io.Reader, maxSize int64) (*Manifest, error) {
	if maxSize <= 0 {
		maxSize = DefaultMaxManifestSize
	}

	data, err := io.ReadAll(io.LimitReader(r, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}

	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("manifest exceeds the maximum accepted size of %d bytes", maxSize)
	}

	return ParseBytes(data)
}

// ParseBytes decodes a manifest from an in-memory JSON document.
func ParseBytes(data []byte) (*Manifest, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("manifest is empty")
	}

	var m Manifest

	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}

	// Reject trailing content so that a manifest cannot smuggle a second
	// document past the parser.
	if err := ensureNoTrailingJSON(dec); err != nil {
		return nil, err
	}

	return &m, nil
}

func ensureNoTrailingJSON(dec *json.Decoder) error {
	var extra json.RawMessage

	err := dec.Decode(&extra)
	switch {
	case errors.Is(err, io.EOF):
		return nil
	case err != nil:
		return fmt.Errorf("decode manifest: trailing data: %w", err)
	default:
		return errors.New("decode manifest: unexpected trailing JSON document")
	}
}

// MajorVersion returns the major component of the declared schema version.
func (m *Manifest) MajorVersion() (int, error) {
	v := strings.TrimSpace(m.Version)
	if v == "" {
		return 0, errors.New("manifest version is missing")
	}

	major, _, _ := strings.Cut(v, ".")

	n, err := strconv.Atoi(major)
	if err != nil {
		return 0, fmt.Errorf("manifest version %q is not a valid schema version", m.Version)
	}

	return n, nil
}

// ItemsByPosition returns the certified items sorted by ascending position,
// which is the leaf ordering of the proof Merkle tree.
//
// The returned slice is a copy; the manifest is left untouched.
func (m *Manifest) ItemsByPosition() []Item {
	items := make([]Item, len(m.Items))
	copy(items, m.Items)

	sort.SliceStable(items, func(i, j int) bool { return items[i].Position < items[j].Position })

	return items
}

// Leaves returns the certified leaf hashes in ascending item position order.
//
// These are the values declared by the manifest. They must not be used to
// rebuild the proof Merkle tree when the original source files are available:
// in that case the tree is rebuilt from the recomputed source digests.
func (m *Manifest) Leaves() [][]byte {
	items := m.ItemsByPosition()

	leaves := make([][]byte, 0, len(items))
	for _, it := range items {
		leaves = append(leaves, it.LeafHash.Bytes())
	}

	return leaves
}

// Anchors returns the declared blockchain anchors.
func (m *Manifest) Anchors() []Anchor {
	return m.Notarization.BlockchainAnchors
}

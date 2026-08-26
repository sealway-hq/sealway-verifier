// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package prooftest

import (
	"archive/zip"
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sealway-hq/sealway-verifier/packages/verifier/merkle"
)

// File is one original file certified by a generated proof.
type File struct {
	Name    string
	Content []byte
}

// Proof is a fully generated synthetic proof.
type Proof struct {
	PublicID string
	Files    []File

	// Manifest is the JSON proof manifest.
	Manifest []byte
	// Token is the DER RFC 3161 artifact.
	Token []byte
	// Certificate is the certificate document embedding both artifacts.
	Certificate []byte

	// MerkleRoot is the proof Merkle root of the generated proof.
	MerkleRoot []byte
	// AccumulatorRoot is the accumulator root the proof root is included in.
	AccumulatorRoot []byte

	// TSA is the throwaway authority that signed the token.
	TSA *TSA
}

// Options configures a generated proof.
type Options struct {
	// PublicID is the public identifier of the proof.
	PublicID string
	// Files are the original files to certify.
	Files []File
	// Anchors are the blockchain anchors declared by the manifest.
	Anchors []Anchor
	// Token overrides the generated RFC 3161 artifact.
	Token []byte
	// TokenOptions configures the generated RFC 3161 artifact.
	TokenOptions *TokenOptions
	// MutateManifest lets a test tamper with the manifest before it is embedded.
	MutateManifest func(m map[string]any)
	// OmitManifest leaves the proof manifest out of the certificate.
	OmitManifest bool
	// OmitToken leaves the timestamp artifact out of the certificate.
	OmitToken bool
	// Revocation embeds long term validation evidence in the certificate: the
	// certification path and a signed statement of the signing certificate's
	// revocation status. Nil embeds none, which is what a proof made before the
	// platform began capturing it looks like.
	Revocation *RevocationOptions
}

// RevocationOptions configures the embedded revocation evidence.
type RevocationOptions struct {
	// Status is the OCSP status to attest: ocsp.Good, ocsp.Revoked or
	// ocsp.Unknown.
	Status int
	// RevokedAt is when the revocation took effect, for a revoked certificate.
	// Zero means one hour before the asserted time.
	RevokedAt time.Time
	// Reason is the RFC 5280 revocation reason code.
	Reason int
	// ThisUpdate is when the answer is current as of. Zero means one hour after
	// the asserted time, which is what a capture made after a grace period looks
	// like.
	ThisUpdate time.Time
	// DelegatedResponder answers with a certificate the authority issued rather
	// than with the authority's own key.
	DelegatedResponder bool
	// OmitOCSPSigningUsage leaves the OCSP signing extended key usage off a
	// delegated responder, which RFC 6960 requires it to carry.
	OmitOCSPSigningUsage bool
	// OmitChain leaves the certification path out while keeping the response.
	OmitChain bool
	// Corrupt flips a byte of the response after signing.
	Corrupt bool
}

// Anchor is a blockchain anchor declared by a generated manifest.
type Anchor struct {
	Network       string
	TransactionID string
	BlockNumber   uint64
}

// DefaultFiles returns a small deterministic set of original files.
func DefaultFiles(n int) []File {
	out := make([]File, 0, n)
	for i := range n {
		out = append(out, File{
			Name:    fmt.Sprintf("document-%d.bin", i),
			Content: bytes.Repeat([]byte{byte(i + 1)}, 64+i),
		})
	}

	return out
}

// New builds a complete synthetic proof.
func New(opts Options) (*Proof, error) {
	if opts.PublicID == "" {
		opts.PublicID = "SW-2026-TEST0001"
	}

	if len(opts.Files) == 0 {
		opts.Files = DefaultFiles(1)
	}

	leaves := make([][]byte, 0, len(opts.Files))
	for _, f := range opts.Files {
		sum := sha512.Sum512(f.Content)
		leaves = append(leaves, sum[:])
	}

	root, err := merkle.ComputeRoot(leaves)
	if err != nil {
		return nil, err
	}

	// The accumulator holds a single leaf, the proof root, so its inclusion path
	// is the duplicated root itself.
	accRoot, err := merkle.ComputeRoot([][]byte{root})
	if err != nil {
		return nil, err
	}

	tsa, err := NewTSA()
	if err != nil {
		return nil, err
	}

	token := opts.Token
	if token == nil {
		tokenOpts := TokenOptions{Imprint: root}
		if opts.TokenOptions != nil {
			tokenOpts = *opts.TokenOptions
			if len(tokenOpts.Imprint) == 0 {
				tokenOpts.Imprint = root
			}
		}

		if token, err = tsa.Token(tokenOpts); err != nil {
			return nil, err
		}
	}

	manifest, err := buildManifest(opts, leaves, root, accRoot)
	if err != nil {
		return nil, err
	}

	attachments := make([]Attachment, 0, 2)
	if !opts.OmitManifest {
		attachments = append(attachments, Attachment{
			Name:        ManifestAttachmentName,
			Description: "Structured proof manifest",
			Content:     manifest,
		})
	}

	if !opts.OmitToken {
		attachments = append(attachments, Attachment{
			Name:        TimestampAttachmentName,
			Description: "RFC 3161 timestamp token over the proof root",
			Content:     token,
		})
	}

	if opts.Revocation != nil {
		evidence, rErr := tsa.revocationEvidence(*opts.Revocation)
		if rErr != nil {
			return nil, rErr
		}

		attachments = append(attachments, evidence...)
	}

	cert, err := BuildCertificate(opts.PublicID, attachments)
	if err != nil {
		return nil, err
	}

	return &Proof{
		PublicID:        opts.PublicID,
		Files:           opts.Files,
		Manifest:        manifest,
		Token:           token,
		Certificate:     cert,
		MerkleRoot:      root,
		AccumulatorRoot: accRoot,
		TSA:             tsa,
	}, nil
}

func buildManifest(opts Options, leaves [][]byte, root, accRoot []byte) ([]byte, error) {
	generated := time.Date(2026, time.August, 14, 8, 33, 7, 0, time.UTC)

	items := make([]any, 0, len(leaves))

	var total int64

	for i, f := range opts.Files {
		siblings, _, err := merkle.GenerateProof(leaves, i)
		if err != nil {
			return nil, err
		}

		total += int64(len(f.Content))

		items = append(items, map[string]any{
			"position":       i,
			"kind":           "document",
			"filename":       f.Name,
			"mime_type":      "application/octet-stream",
			"size_bytes":     len(f.Content),
			"hash_sha512":    hex.EncodeToString(leaves[i]),
			"leaf_hash":      hex.EncodeToString(leaves[i]),
			"source_status":  "source_retained",
			"source_present": true,
			"source_type":    "file_import",
			"merkle_proof": map[string]any{
				"leaf_index":     i,
				"hash_algorithm": "SHA512",
				"siblings":       encodeSiblings(siblings),
			},
		})
	}

	inclusion, _, err := merkle.GenerateProof([][]byte{root}, 0)
	if err != nil {
		return nil, err
	}

	anchors := make([]any, 0, len(opts.Anchors))
	for _, a := range opts.Anchors {
		anchors = append(anchors, map[string]any{
			"provider_name":  a.Network,
			"transaction_id": a.TransactionID,
			"block_number":   a.BlockNumber,
			"status":         "anchored",
			"anchored_at":    generated.Format(time.RFC3339Nano),
		})
	}

	m := map[string]any{
		"version":      "1.1",
		"generated_at": generated.Format(time.RFC3339Nano),
		"partial":      false,
		"proof": map[string]any{
			"id":               "019fff63-4f2e-704a-aec5-000000000000",
			"public_id":        opts.PublicID,
			"category":         "file",
			"title":            "Synthetic test proof",
			"hash_algorithm":   "SHA-512",
			"merkle_root":      hex.EncodeToString(root),
			"item_count":       len(opts.Files),
			"total_size_bytes": total,
			"created_at":       generated.Format(time.RFC3339Nano),
			"timestamped_at":   DefaultGenTime.Format(time.RFC3339Nano),
		},
		"items": items,
		"notarization": map[string]any{
			"provider":              "test",
			"external_id":           "019fff64-bbbf-717c-90b5-000000000000",
			"algorithm":             "SHA-512",
			"hash":                  hex.EncodeToString(root),
			"merkle_root":           hex.EncodeToString(root),
			"accumulator_root":      hex.EncodeToString(accRoot),
			"accumulator_sealed_at": generated.Format(time.RFC3339Nano),
			"notarized_at":          DefaultGenTime.Format(time.RFC3339Nano),
			"proof_timestamp": map[string]any{
				"tsa_provider_name": "test",
				"cert_subject":      "CN=Sealway Verifier Test TSU",
				"policy_oid":        DefaultPolicyOID.String(),
				"serial_number":     "4242",
				"timestamped_at":    DefaultGenTime.Format(time.RFC3339Nano),
			},
			"inclusion_proof": map[string]any{
				"leaf_index":     0,
				"hash_algorithm": "SHA512",
				"siblings":       encodeSiblings(inclusion),
			},
			"blockchain_anchors": anchors,
		},
	}

	if opts.MutateManifest != nil {
		opts.MutateManifest(m)
	}

	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("prooftest: cannot encode the manifest: %w", err)
	}

	return out, nil
}

func encodeSiblings(siblings []merkle.Sibling) []any {
	out := make([]any, 0, len(siblings))
	for _, s := range siblings {
		out = append(out, map[string]any{
			"position": s.Direction.String(),
			"hash":     hex.EncodeToString(s.Hash),
		})
	}

	return out
}

// BundleOptions configures a generated proof bundle archive.
type BundleOptions struct {
	// OmitCertificate leaves the certificate out of the archive.
	OmitCertificate bool
	// ExtraCertificates adds further candidate certificates, making the archive
	// ambiguous.
	ExtraCertificates int
	// OmitSources leaves the original files out of the archive.
	OmitSources bool
	// LooseManifest overrides the convenience copy of the manifest.
	LooseManifest []byte
	// OmitLooseCopies leaves the convenience copies out of the archive.
	OmitLooseCopies bool
	// ExtraEntries adds arbitrary entries, for hostile archive tests.
	ExtraEntries map[string][]byte
}

// Bundle assembles the proof into a bundle archive.
func (p *Proof) Bundle(opts BundleOptions) ([]byte, error) {
	var buf bytes.Buffer

	zw := zip.NewWriter(&buf)

	write := func(name string, data []byte) error {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}

		_, err = w.Write(data)

		return err
	}

	if !opts.OmitCertificate {
		if err := write("sealway-certificate-"+p.PublicID+".pdf", p.Certificate); err != nil {
			return nil, err
		}
	}

	for i := range opts.ExtraCertificates {
		name := fmt.Sprintf("sealway-certificate-%s-copy%d.pdf", p.PublicID, i)
		if err := write(name, p.Certificate); err != nil {
			return nil, err
		}
	}

	if !opts.OmitLooseCopies {
		manifest := opts.LooseManifest
		if manifest == nil {
			manifest = p.Manifest
		}

		if err := write("sealway-proof.json", manifest); err != nil {
			return nil, err
		}

		if err := write("proof-timestamp.tsr", p.Token); err != nil {
			return nil, err
		}
	}

	if !opts.OmitSources {
		for _, f := range p.Files {
			if err := write("files/"+f.Name, f.Content); err != nil {
				return nil, err
			}
		}
	}

	for name, data := range opts.ExtraEntries {
		if err := write(name, data); err != nil {
			return nil, err
		}
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

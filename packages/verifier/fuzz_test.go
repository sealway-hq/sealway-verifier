// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package verifier_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/sealway-hq/sealway-verifier/packages/verifier"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/bundle"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/merkle"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/proof"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/timestamp"
)

// The fuzz targets all encode the same requirement: untrusted input must never
// panic the process. A malformed proof is a verification outcome, never a crash.

func FuzzManifestParse(f *testing.F) {
	f.Add([]byte(`{"version":"1.1","proof":{"public_id":"X"},"items":[]}`))
	f.Add([]byte(`{"version":"1.1","proof":{"merkle_root":"` + strings.Repeat("ab", 64) + `"}}`))
	f.Add([]byte(`{"items":[{"position":-1,"leaf_hash":"zz"}]}`))
	f.Add([]byte(`{"notarization":{"inclusion_proof":{"siblings":[{"position":"up","hash":"00"}]}}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		m, err := proof.ParseBytes(data)
		if err != nil {
			return
		}

		// Every accessor must remain safe on a parsed but unvalidated manifest.
		_ = m.Validate()
		_, _ = m.MajorVersion()
		_ = m.ItemsByPosition()
		_ = m.Leaves()
		_ = m.Anchors()
	})
}

func FuzzHashUnmarshal(f *testing.F) {
	f.Add(`"abcd"`)
	f.Add(`"` + strings.Repeat("ff", 64) + `"`)
	f.Add(`""`)
	f.Add(`123`)
	f.Add(`"zz"`)
	f.Add(`null`)

	f.Fuzz(func(_ *testing.T, s string) {
		var h proof.Hash
		if err := h.UnmarshalJSON([]byte(s)); err != nil {
			return
		}

		_ = h.String()
		_ = h.IsZero()
		_ = h.Equal(h)
		_, _ = h.MarshalJSON()
	})
}

func FuzzMerkleProofVerify(f *testing.F) {
	root := bytes.Repeat([]byte{0x11}, merkle.DigestSize)
	leaf := bytes.Repeat([]byte{0x22}, merkle.DigestSize)

	f.Add(leaf, root, []byte{0x01}, uint(1))
	f.Add(leaf, root, bytes.Repeat([]byte{0x33}, merkle.DigestSize), uint(3))
	f.Add([]byte{}, []byte{}, []byte{}, uint(0))

	f.Fuzz(func(_ *testing.T, leaf, root, sibling []byte, directions uint) {
		count := int(directions % (merkle.MaxSiblings + 2))

		siblings := make([]merkle.Sibling, 0, count)
		for i := range count {
			d := merkle.Left
			if directions>>(uint(i)%32)&1 == 1 {
				d = merkle.Right
			}

			siblings = append(siblings, merkle.Sibling{Direction: d, Hash: sibling})
		}

		_, _ = merkle.VerifyProof(leaf, siblings, root)
		_, _ = merkle.RootFromProof(leaf, siblings)
		_, _ = merkle.ComputeRoot([][]byte{leaf, root, sibling})
	})
}

func FuzzTimestampParse(f *testing.F) {
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x00})
	f.Add([]byte("not der at all"))
	f.Add([]byte{})

	if der, err := hex.DecodeString("30820fbe06092a864886f70d010702"); err == nil {
		f.Add(der)
	}

	f.Fuzz(func(_ *testing.T, data []byte) {
		token, err := timestamp.Parse(data)
		if err != nil {
			return
		}

		_ = token.VerifySignature()
		_ = token.VerifyImprint(data)
		_ = token.SignerSubject()
		_ = token.SignerIssuer()
		_ = token.HasTimestampingUsage()
	})
}

func FuzzBundleOpen(f *testing.F) {
	f.Add([]byte("PK\x03\x04"))
	f.Add([]byte{})
	f.Add([]byte("PK\x05\x06" + strings.Repeat("\x00", 18)))

	f.Fuzz(func(_ *testing.T, data []byte) {
		b, err := bundle.Open(bytes.NewReader(data), int64(len(data)), bundle.Limits{})
		if err != nil {
			return
		}

		_, _ = b.Certificate()
		_ = b.Sources()
		_ = b.Entries()
		_, _ = b.LooseCopy(bundle.LooseManifestName)
	})
}

// FuzzVerifyBundle drives the whole pipeline with arbitrary archives, which is
// the broadest guarantee: no shape of hostile bundle takes the process down.
func FuzzVerifyBundle(f *testing.F) {
	f.Add([]byte("PK\x03\x04"))
	f.Add([]byte("PK\x05\x06" + strings.Repeat("\x00", 18)))
	f.Add([]byte{})

	v := verifier.New(verifier.WithOffline())

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}

		_, _ = v.VerifyBundle(t.Context(), bytes.NewReader(data), int64(len(data)))
	})
}

// FuzzVerifyCertificate drives the pipeline with arbitrary documents.
func FuzzVerifyCertificate(f *testing.F) {
	f.Add([]byte("%PDF-1.7\n"))
	f.Add([]byte("%PDF-1.7\ntrailer<</Root 1 0 R>>\nstartxref\n0\n%%EOF"))
	f.Add([]byte{})

	v := verifier.New(verifier.WithOffline())

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = v.VerifyCertificate(t.Context(), bytes.NewReader(data), nil)
	})
}

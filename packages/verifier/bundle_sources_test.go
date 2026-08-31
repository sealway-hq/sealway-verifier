// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package verifier_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealway-hq/sealway-verifier/internal/prooftest"
	"github.com/sealway-hq/sealway-verifier/packages/verifier"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/report"
)

// sourceOf builds a source from bytes held in memory, which is what a caller
// that never touches a filesystem has.
func sourceOf(name string, content []byte) verifier.Source {
	return verifier.Source{
		Name:     name,
		Size:     int64(len(content)),
		Explicit: true,
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(content)), nil
		},
	}
}

// TestVerifyBundleAcceptsSourcesSuppliedBesideIt covers the archive that carries
// a certificate and nothing else, which is what a person is given when the
// original files were too large to ship with the proof.
//
// The files reach the same checks whether the archive carried them or the caller
// handed them over: where the bytes came from is transport, and the verdict is
// about their digests.
func TestVerifyBundleAcceptsSourcesSuppliedBesideIt(t *testing.T) {
	t.Parallel()

	files := prooftest.DefaultFiles(2)
	p := newProof(t, prooftest.Options{Files: files})
	v := verifier.New(verifier.WithOffline())

	stripped, err := p.Bundle(prooftest.BundleOptions{OmitSources: true})
	require.NoError(t, err)

	// Without the files, the source dependent steps have nothing to work from.
	bare, err := v.VerifyBundle(t.Context(), bytes.NewReader(stripped), int64(len(stripped)))
	require.NoError(t, err)
	require.Equal(t, report.StatusSkipped, statusOf(t, bare, "sources.availability"))

	supplied := make([]verifier.Source, 0, len(files))
	for _, f := range files {
		supplied = append(supplied, sourceOf(f.Name, f.Content))
	}

	with, err := v.VerifyBundle(t.Context(),
		bytes.NewReader(stripped), int64(len(stripped)), supplied...)
	require.NoError(t, err)

	assert.Equal(t, report.StatusValid, statusOf(t, with, "sources.availability"))
	assert.Equal(t, report.StatusValid, statusOf(t, with, "sources.item.0"))
	assert.Equal(t, report.StatusValid, statusOf(t, with, "proof_merkle.leaf_hashes"))

	// And it reaches exactly what the archive carrying its own files reaches.
	complete, err := p.Bundle(prooftest.BundleOptions{})
	require.NoError(t, err)

	full, err := v.VerifyBundle(t.Context(), bytes.NewReader(complete), int64(len(complete)))
	require.NoError(t, err)

	for _, c := range full.Sections {
		for _, want := range c.Checks {
			if want.ID == "certificate.loose_copies" {
				continue // compares copies only an archive carries
			}

			assert.Equal(t, want.Status, statusOf(t, with, want.ID), "check %s", want.ID)
		}
	}
}

// TestSuppliedSourcesAreVerifiedNotBelieved is the negative half: a file handed
// over beside a proof is evidence to be hashed, never a claim to be accepted.
func TestSuppliedSourcesAreVerifiedNotBelieved(t *testing.T) {
	t.Parallel()

	files := prooftest.DefaultFiles(1)
	p := newProof(t, prooftest.Options{Files: files})

	stripped, err := p.Bundle(prooftest.BundleOptions{OmitSources: true})
	require.NoError(t, err)

	tampered := append([]byte(nil), files[0].Content...)
	tampered[0] ^= 0xff

	r, err := verifier.New(verifier.WithOffline()).VerifyBundle(t.Context(),
		bytes.NewReader(stripped), int64(len(stripped)),
		sourceOf(files[0].Name, tampered))
	require.NoError(t, err)

	assert.Equal(t, report.StatusInvalid, statusOf(t, r, "sources.item.0"))
	assert.Equal(t, report.ResultInvalid, r.Result)
}

// TestVerifyBundleRefusesASourceItAlreadyCarries keeps an ambiguity from being
// resolved silently.
//
// Two different byte streams claiming to be the same certified item cannot both
// be it. Picking one and reporting valid because that one matched would hide
// that the caller handed over a file which is not the certified original.
func TestVerifyBundleRefusesASourceItAlreadyCarries(t *testing.T) {
	t.Parallel()

	files := prooftest.DefaultFiles(1)
	p := newProof(t, prooftest.Options{Files: files})

	complete, err := p.Bundle(prooftest.BundleOptions{})
	require.NoError(t, err)

	_, err = verifier.New(verifier.WithOffline()).VerifyBundle(t.Context(),
		bytes.NewReader(complete), int64(len(complete)),
		sourceOf(files[0].Name, files[0].Content))
	require.ErrorIs(t, err, verifier.ErrInvalidInput)
	assert.Contains(t, err.Error(), files[0].Name)
}

// TestInputCarriesSourcesForABundleToo keeps the generic entry point from being
// the one door that still drops them.
//
// The premise it used to reject on — that a bundle already carries its files —
// is false for the archive that ships a certificate and nothing else.
func TestInputCarriesSourcesForABundleToo(t *testing.T) {
	t.Parallel()

	files := prooftest.DefaultFiles(1)
	p := newProof(t, prooftest.Options{Files: files})

	stripped, err := p.Bundle(prooftest.BundleOptions{OmitSources: true})
	require.NoError(t, err)

	r, err := verifier.New(verifier.WithOffline()).Verify(t.Context(), verifier.Input{
		Bundle:     bytes.NewReader(stripped),
		BundleSize: int64(len(stripped)),
		Sources:    []verifier.Source{sourceOf(files[0].Name, files[0].Content)},
	})
	require.NoError(t, err)

	assert.Equal(t, report.StatusValid, statusOf(t, r, "sources.item.0"))
}

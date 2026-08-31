// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package verifier

import (
	"errors"
	"fmt"
	"io"
)

// Source gives the verifier access to one original file supplied by the caller.
//
// The verifier never opens a path itself: it reads through the Open callback, so
// a file on disk, an entry inside a bundle archive and a buffer handed over by a
// browser are all supplied the same way.
type Source struct {
	// Name is the file name used for deterministic matching against the
	// certified items. It is normally the base name of the original file.
	Name string
	// Size is the size in bytes when known, or a negative value when unknown.
	Size int64
	// Open returns a fresh reader over the raw file bytes. It may be called more
	// than once and the caller of Open closes the reader.
	Open func() (io.ReadCloser, error)
	// Explicit reports whether the caller designated this file as part of the
	// proof, as opposed to having discovered it while scanning a directory.
	//
	// An explicitly designated file that matches no certified item is a failing
	// check, because the caller asserted that it belongs to the proof. A file
	// merely discovered in a directory is ignored instead.
	Explicit bool
}

// Input describes what should be verified.
//
// Exactly one of Bundle and Certificate must be set. Sources are only meaningful
// alongside a certificate: a bundle carries its own original files.
type Input struct {
	// Bundle is a proof bundle archive.
	Bundle io.ReaderAt
	// BundleSize is the size in bytes of the bundle archive.
	BundleSize int64
	// Certificate is a Sealway certificate document.
	Certificate io.ReadSeeker
	// Sources are the original files supplied alongside the proof, whether that
	// proof is a certificate or a bundle. A bundle that ships a certificate and
	// nothing else carries no files of its own, so supplying them is the only way
	// to reach a complete verdict on one.
	Sources []Source
}

// ErrInvalidInput is returned when the supplied input cannot be verified at all.
var ErrInvalidInput = errors.New("verifier: invalid input")

func (in Input) validate() error {
	switch {
	case in.Bundle == nil && in.Certificate == nil:
		return errors.New("verifier: either a proof bundle or a certificate must be supplied")
	case in.Bundle != nil && in.Certificate != nil:
		return errors.New("verifier: a proof bundle and a certificate cannot be verified together")
	case in.Bundle != nil && in.BundleSize <= 0:
		return errors.New("verifier: the proof bundle size must be known")
	}

	for i, s := range in.Sources {
		if s.Name == "" {
			return fmt.Errorf("verifier: source %d has no name", i)
		}

		if s.Open == nil {
			return fmt.Errorf("verifier: source %q has no reader", s.Name)
		}
	}

	return nil
}

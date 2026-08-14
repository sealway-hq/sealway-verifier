// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

// Package source builds verifier sources from the local filesystem.
//
// It is deliberately separate from the verifier package: the core verification
// logic never touches the filesystem, so it stays reusable from a browser
// WebAssembly build. Front ends that do have a filesystem use this package.
package source

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/sealway-hq/sealway-verifier/packages/verifier"
)

// MaxDirEntries bounds how many files a directory scan will consider.
const MaxDirEntries = 100000

// FromPath returns a source for one file the caller explicitly designated as
// part of the proof.
//
// Because the caller designated it, a file that matches no certified item is
// reported as a failing check rather than silently ignored.
func FromPath(path string) (verifier.Source, error) {
	info, err := os.Stat(path)
	if err != nil {
		return verifier.Source{}, fmt.Errorf("source: cannot read %q: %w", path, err)
	}

	if info.IsDir() {
		return verifier.Source{}, fmt.Errorf("source: %q is a directory, not a file", path)
	}

	if !info.Mode().IsRegular() {
		return verifier.Source{}, fmt.Errorf("source: %q is not a regular file", path)
	}

	return newSource(path, info.Size(), true), nil
}

// FromPaths returns sources for several explicitly designated files.
func FromPaths(paths []string) ([]verifier.Source, error) {
	out := make([]verifier.Source, 0, len(paths))

	for _, p := range paths {
		s, err := FromPath(p)
		if err != nil {
			return nil, err
		}

		out = append(out, s)
	}

	return out, nil
}

// FromDir returns sources for the regular files found under a directory.
//
// The scan is recursive and skips symbolic links and every other irregular
// entry, so it cannot be led outside the directory it was pointed at. Files
// discovered this way are not designated by the caller, so a file that matches
// no certified item is simply disregarded instead of being reported as a
// finding: a directory may legitimately hold unrelated files.
func FromDir(dir string) ([]verifier.Source, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("source: cannot read %q: %w", dir, err)
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("source: %q is not a directory", dir)
	}

	var out []verifier.Source

	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		// Only regular files are considered. A symbolic link is skipped rather
		// than followed so that a prepared directory cannot make the verifier
		// read something outside it.
		if !d.Type().IsRegular() {
			return nil
		}

		fi, err := d.Info()
		if err != nil {
			return err
		}

		out = append(out, newSource(path, fi.Size(), false))

		if len(out) > MaxDirEntries {
			return fmt.Errorf("source: %q holds more than %d files", dir, MaxDirEntries)
		}

		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("source: cannot scan %q: %w", dir, walkErr)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

	return out, nil
}

func newSource(path string, size int64, explicit bool) verifier.Source {
	return verifier.Source{
		Name:     filepath.Base(path),
		Size:     size,
		Explicit: explicit,
		Open: func() (io.ReadCloser, error) {
			f, err := os.Open(path)
			if err != nil {
				return nil, fmt.Errorf("source: cannot open %q: %w", path, err)
			}

			return f, nil
		},
	}
}

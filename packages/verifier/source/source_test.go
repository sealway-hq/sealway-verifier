// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package source_test

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealway-hq/sealway-verifier/packages/verifier/source"
)

func write(t *testing.T, path, content string) string {
	t.Helper()

	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	return path
}

func TestFromPath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := write(t, filepath.Join(dir, "document.pdf"), "hello")

	s, err := source.FromPath(path)
	require.NoError(t, err)

	assert.Equal(t, "document.pdf", s.Name)
	assert.Equal(t, int64(5), s.Size)
	assert.True(t, s.Explicit, "a designated file must be reported when it matches nothing")

	rc, err := s.Open()
	require.NoError(t, err)

	defer func() { _ = rc.Close() }()

	data, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(data))
}

func TestFromPathRejectsNonFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	_, err := source.FromPath(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "directory")

	_, err = source.FromPath(filepath.Join(dir, "missing.bin"))
	assert.Error(t, err)
}

func TestFromPaths(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	a := write(t, filepath.Join(dir, "a.bin"), "a")
	b := write(t, filepath.Join(dir, "b.bin"), "bb")

	sources, err := source.FromPaths([]string{a, b})
	require.NoError(t, err)
	require.Len(t, sources, 2)
	assert.Equal(t, "a.bin", sources[0].Name)
	assert.Equal(t, "b.bin", sources[1].Name)

	_, err = source.FromPaths([]string{a, filepath.Join(dir, "missing")})
	assert.Error(t, err)
}

func TestFromDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	write(t, filepath.Join(dir, "b.bin"), "b")
	write(t, filepath.Join(dir, "a.bin"), "a")
	write(t, filepath.Join(dir, "nested", "c.bin"), "c")

	sources, err := source.FromDir(dir)
	require.NoError(t, err)
	require.Len(t, sources, 3)

	// The scan is deterministic and recursive.
	assert.Equal(t, "a.bin", sources[0].Name)
	assert.Equal(t, "b.bin", sources[1].Name)
	assert.Equal(t, "c.bin", sources[2].Name)

	for _, s := range sources {
		assert.False(t, s.Explicit,
			"a discovered file must be disregarded when it matches nothing")
	}
}

// TestFromDirSkipsSymlinks checks that a prepared directory cannot make the
// verifier read a file outside it.
func TestFromDirSkipsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links require elevated privileges on Windows")
	}

	t.Parallel()

	outside := t.TempDir()
	secret := write(t, filepath.Join(outside, "secret.txt"), "secret")

	dir := t.TempDir()
	write(t, filepath.Join(dir, "real.bin"), "real")
	require.NoError(t, os.Symlink(secret, filepath.Join(dir, "link.txt")))
	require.NoError(t, os.Symlink(outside, filepath.Join(dir, "linkdir")))

	sources, err := source.FromDir(dir)
	require.NoError(t, err)
	require.Len(t, sources, 1)
	assert.Equal(t, "real.bin", sources[0].Name)
}

func TestFromDirRejectsNonDirectories(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := write(t, filepath.Join(dir, "a.bin"), "a")

	_, err := source.FromDir(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a directory")

	_, err = source.FromDir(filepath.Join(dir, "missing"))
	assert.Error(t, err)
}

func TestFromDirEmpty(t *testing.T) {
	t.Parallel()

	sources, err := source.FromDir(t.TempDir())
	require.NoError(t, err)
	assert.Empty(t, sources)
}

func TestOpenIsRepeatable(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := write(t, filepath.Join(dir, "a.bin"), "payload")

	s, err := source.FromPath(path)
	require.NoError(t, err)

	for range 3 {
		rc, err := s.Open()
		require.NoError(t, err)

		data, err := io.ReadAll(rc)
		require.NoError(t, err)
		require.NoError(t, rc.Close())
		assert.Equal(t, "payload", string(data))
	}
}

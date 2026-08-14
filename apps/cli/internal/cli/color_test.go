// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package cli

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestColorDecision pins the colour policy, including honouring NO_COLOR. Status
// is always spelled out as well, so suppressing colour never loses information.
func TestColorDecision(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name                                     string
		noColorFlag, jsonOutput, noColorEnv, tty bool
		want                                     bool
	}{
		{name: "interactive terminal", tty: true, want: true},
		{name: "piped output", want: false},
		{name: "no-color flag", noColorFlag: true, tty: true, want: false},
		{name: "json output", jsonOutput: true, tty: true, want: false},
		{name: "NO_COLOR set", noColorEnv: true, tty: true, want: false},
		{name: "NO_COLOR beats everything", noColorEnv: true, want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := colorDecision(tc.noColorFlag, tc.jsonOutput, tc.noColorEnv, tc.tty)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestIsTerminal(t *testing.T) {
	t.Parallel()

	assert.False(t, isTerminal(&bytes.Buffer{}))

	f, err := os.CreateTemp(t.TempDir(), "out")
	assert.NoError(t, err)

	t.Cleanup(func() { _ = f.Close() })

	assert.False(t, isTerminal(f), "a regular file is not an interactive terminal")
}

func TestUseColorReadsNoColorFromTheEnvironment(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	assert.False(t, useColor(&verifyFlags{}, Streams{Out: os.Stdout}))
}

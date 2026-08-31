// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

//go:build js && wasm

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"strings"
	"syscall/js"

	"github.com/sealway-hq/sealway-verifier/packages/verifier"
)

// containerKind is what a caller dropped on the page.
type containerKind int

const (
	containerUnknown containerKind = iota
	containerBundle
	containerCertificate
)

// container reads the first bytes to tell a proof bundle from a certificate.
//
// A page asks people for "their proof", and they supply whichever of the two
// files they were given. Refusing the certificate with "not a valid zip file"
// answers a question nobody asked; naming what was received lets the caller say
// something useful.
func container(data []byte) containerKind {
	switch {
	case bytes.HasPrefix(data, []byte("PK\x03\x04")),
		bytes.HasPrefix(data, []byte("PK\x05\x06")),
		bytes.HasPrefix(data, []byte("PK\x07\x08")):
		return containerBundle
	case bytes.HasPrefix(data, []byte("%PDF-")):
		return containerCertificate
	default:
		return containerUnknown
	}
}

// encode renders a report as the canonical JSON the host consumes.
func encode(v any) (any, error) {
	out, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	return string(out), nil
}

// verifyTimestamp checks a bare RFC 3161 artifact.
func verifyTimestamp(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return rejected("verifyTimestamp expects the token as its first argument")
	}

	token, err := toArtifact(args[0])
	if err != nil {
		return rejected(err.Error())
	}

	var options js.Value
	if len(args) > 1 {
		options = args[1]
	}

	opts, err := buildOptions(options)
	if err != nil {
		return rejected(err.Error())
	}

	in := verifier.TimestampInput{Token: token}

	// Declared as bytes or hexadecimal, because a digest is as often written down
	// as it is held: toDigest reads either.
	if in.Imprint, err = toDigest(options.Get("imprint")); err != nil {
		return rejected(fmt.Errorf("imprint: %w", err).Error())
	}

	if in.Chain, err = toBytes(options.Get("chain")); err != nil {
		return rejected(fmt.Errorf("chain: %w", err).Error())
	}

	if in.Revocation, err = toByteList(options.Get("revocation")); err != nil {
		return rejected(fmt.Errorf("revocation: %w", err).Error())
	}

	return promise(func() (any, error) {
		report, err := verifier.New(opts...).VerifyTimestamp(context.Background(), in)
		if err != nil {
			return nil, err
		}

		return encode(report)
	})
}

// inspectTimestamp decodes a token without judging it.
func inspectTimestamp(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return rejected("inspectTimestamp expects the token as its first argument")
	}

	token, err := toArtifact(args[0])
	if err != nil {
		return rejected(err.Error())
	}

	return promise(func() (any, error) {
		details, err := verifier.InspectTimestamp(token)
		if err != nil {
			return nil, err
		}

		return encode(details)
	})
}

// requiredTerritory names the national Trusted List a token needs, so that a
// host serving trust material fetches one list rather than every list the
// European Union publishes.
func requiredTerritory(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return rejected("requiredTerritory expects the token as its first argument")
	}

	token, err := toArtifact(args[0])
	if err != nil {
		return rejected(err.Error())
	}

	return promise(func() (any, error) {
		return verifier.RequiredTerritory(token)
	})
}

// verifyMerkle answers a question about the Merkle profile alone: rebuild a root
// from digests, or check that one leaf belongs to a tree.
func verifyMerkle(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return rejected("verifyMerkle expects its input as its first argument")
	}

	in, err := toMerkleInput(args[0])
	if err != nil {
		return rejected(err.Error())
	}

	return promise(func() (any, error) {
		report, err := verifier.VerifyMerkle(in)
		if err != nil {
			return nil, err
		}

		return encode(report)
	})
}

func toMerkleInput(v js.Value) (verifier.MerkleInput, error) {
	var in verifier.MerkleInput

	if v.IsUndefined() || v.IsNull() {
		return in, errors.New("verifyMerkle expects an object describing what to check")
	}

	var err error

	if in.Leaves, err = toByteList(v.Get("leaves")); err != nil {
		return in, fmt.Errorf("leaves: %w", err)
	}

	if in.Leaf, err = toDigest(v.Get("leaf")); err != nil {
		return in, fmt.Errorf("leaf: %w", err)
	}

	if in.Root, err = toDigest(v.Get("root")); err != nil {
		return in, fmt.Errorf("root: %w", err)
	}

	path := v.Get("path")
	if path.IsUndefined() || path.IsNull() {
		return in, nil
	}

	for i := range path.Length() {
		item := path.Index(i)

		digest, err := toDigest(item.Get("digest"))
		if err != nil {
			return in, fmt.Errorf("path[%d].digest: %w", i, err)
		}

		// A sibling without a side cannot be folded: the profile hashes
		// SHA-512(0x01 || left || right), so which of the two the sibling is
		// changes the result.
		side := strings.ToLower(item.Get("position").String())

		switch side {
		case "left":
			in.Path = append(in.Path, verifier.MerkleSibling{
				Hash: digest, Direction: verifier.MerkleLeft,
			})
		case "right":
			in.Path = append(in.Path, verifier.MerkleSibling{
				Hash: digest, Direction: verifier.MerkleRight,
			})
		default:
			return in, fmt.Errorf(
				"path[%d].position is %q, and must be \"left\" or \"right\": which side a sibling "+
					"sits on changes the value it folds to", i, side)
		}
	}

	return in, nil
}

// toArtifact accepts a token however a page happens to hold it.
//
// A .tsr file gives bytes; a JSON payload or a clipboard paste gives base64 or
// hexadecimal. Refusing the last two would push the decoding onto every caller,
// and getting it wrong there produces "malformed artifact" rather than "that is
// not base64".
func toArtifact(v js.Value) ([]byte, error) {
	if v.Type() == js.TypeString {
		return decodeText(v.String())
	}

	data, err := toBytes(v)
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return nil, errors.New("the timestamp artifact is empty")
	}

	return data, nil
}

// decodeText reads a token written as text, in whichever of the two encodings
// people paste.
func decodeText(s string) ([]byte, error) {
	trimmed := strings.Join(strings.Fields(s), "")
	if trimmed == "" {
		return nil, errors.New("the timestamp artifact is empty")
	}

	// PEM armour, which a few tools emit around a token.
	if strings.Contains(s, "-----BEGIN") {
		var body strings.Builder

		for _, line := range strings.Split(s, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "-----") {
				body.WriteString(strings.TrimSpace(line))
			}
		}

		trimmed = body.String()
	}

	if der, err := hex.DecodeString(trimmed); err == nil && len(der) > 0 {
		return der, nil
	}

	der, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		return nil, errors.New(
			"the timestamp artifact is text but is neither base64 nor hexadecimal")
	}

	return der, nil
}

// toDigest reads a digest given as bytes or as hexadecimal text.
func toDigest(v js.Value) ([]byte, error) {
	if v.Type() == js.TypeString {
		s := strings.Join(strings.Fields(v.String()), "")
		if s == "" {
			return nil, nil
		}

		out, err := hex.DecodeString(s)
		if err != nil {
			return nil, errors.New("expected a hexadecimal digest")
		}

		return out, nil
	}

	return toBytes(v)
}

// toByteList reads an array of byte arrays, or of hexadecimal strings.
func toByteList(v js.Value) ([][]byte, error) {
	if v.IsUndefined() || v.IsNull() {
		return nil, nil
	}

	out := make([][]byte, 0, v.Length())

	for i := range v.Length() {
		item, err := toDigest(v.Index(i))
		if err != nil {
			return nil, fmt.Errorf("[%d]: %w", i, err)
		}

		out = append(out, item)
	}

	return out, nil
}

// toSources reads original files supplied beside a certificate.
//
// In a browser the natural gesture is to drop the certificate and then add the
// files it certifies. Requiring them to be re-zipped first is a desktop
// operation, and the difference between asking for it and not is the difference
// between a partial verdict and a complete one.
func toSources(v js.Value) ([]verifier.Source, error) {
	if v.IsUndefined() || v.IsNull() {
		return nil, nil
	}

	out := make([]verifier.Source, 0, v.Length())

	for i := range v.Length() {
		item := v.Index(i)

		// String() on an absent property yields "<undefined>" rather than "", so
		// the type is what says whether a name was given at all.
		var name string
		if v := item.Get("name"); v.Type() == js.TypeString {
			name = v.String()
		}

		if name == "" {
			return nil, fmt.Errorf(
				"sources[%d] has no name, and a certified item is matched by the name of the file "+
					"that produced it", i)
		}

		// A certified item is named by its file, not by where a copy of it sat, so
		// "files/report.pdf" designates the same item as "report.pdf". This is what
		// source.FromPath does for the command line tool.
		name = path.Base(filepath.ToSlash(name))

		data, err := toBytes(item.Get("content"))
		if err != nil {
			return nil, fmt.Errorf("sources[%d] (%s): %w", i, name, err)
		}

		if len(data) == 0 {
			return nil, fmt.Errorf("sources[%d] (%s) is empty", i, name)
		}

		out = append(out, verifier.Source{
			Name: name,
			Size: int64(len(data)),
			// A file the caller handed over is asserted to belong to the proof,
			// so one matching no certified item is a finding rather than an
			// unrelated file to pass over.
			Explicit: true,
			Open:     openBytes(data),
		})
	}

	return out, nil
}

func openBytes(data []byte) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	}
}

// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

// Package trust supplies the material needed to authenticate European Trusted
// Lists, separately from how that material is obtained.
//
// The separation is what lets one engine serve every front end. A command line
// tool and a desktop application can fetch the official publications directly; a
// browser cannot, because the official endpoints send no cross-origin headers,
// so it reads the same bytes from a mirror. Either way the bytes are the
// official signed documents and the client verifies their signatures itself, so
// a mirror is a transport and never an authority: it can withhold or delay
// material, but it cannot invent a qualified service.
//
// The core of this package is pure data: it reaches no network and touches no
// filesystem. Those live in the providers, so a caller may supply its own.
package trust

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Errors returned when trust material cannot be supplied.
var (
	// ErrUnavailable is returned when no material could be obtained. It means
	// the question cannot be answered, never that the answer is negative.
	ErrUnavailable = errors.New("trust: no trust material is available")
	// ErrRollback is returned when material is older than material already seen,
	// which is how a mirror or a cache would replay a superseded list.
	ErrRollback = errors.New("trust: the supplied material is older than material already seen")
	// ErrDigestMismatch is returned when material does not match its declared
	// digest.
	ErrDigestMismatch = errors.New("trust: material does not match its declared digest")
)

// Material is the trust material for one assessment.
//
// It carries raw signed documents rather than a digest of somebody's opinion
// about them, so the client can verify what the European authorities actually
// published.
type Material struct {
	// LOTL is the raw signed European List of Trusted Lists.
	LOTL []byte
	// Lists maps a scheme territory to the raw signed national list.
	Lists map[string][]byte
	// Certificates are additional certificates that may complete a
	// certification path, such as issuing authorities fetched separately.
	Certificates []*x509.Certificate
	// Source describes where the material came from, for the report.
	Source string
	// RetrievedAt is when the material was obtained.
	RetrievedAt time.Time
}

// Territories returns the territories the material covers, sorted.
func (m *Material) Territories() []string {
	if m == nil {
		return nil
	}

	out := make([]string, 0, len(m.Lists))
	for t := range m.Lists {
		out = append(out, t)
	}

	slices.Sort(out)

	return out
}

// Request describes what an assessment needs.
type Request struct {
	// ValidationTime is the instant the assessment is about, which is the time
	// the timestamp asserts rather than the moment of verification.
	ValidationTime time.Time
	// Territory is the scheme territory expected to carry the service. It is a
	// hint: a provider may return more.
	Territory string
	// Offline forbids every network access. A provider that cannot answer from
	// what it already holds must return ErrUnavailable rather than reach out.
	Offline bool
}

// Provider supplies trust material.
//
// Implementations must respect Request.Offline and the deadline carried by the
// context, and must never return partially verified material: verification is
// the caller's job and needs the raw documents.
type Provider interface {
	// Material returns the trust material for a request.
	Material(ctx context.Context, req Request) (*Material, error)
	// Describe names the provider for the report.
	Describe() string
}

// Static serves material a caller already holds.
//
// It is what a browser build uses when the host application has fetched the
// documents itself, and what tests use to stay off the network entirely.
type Static struct {
	// Value is the material to serve.
	Value *Material
	// Name describes the source in the report.
	Name string
}

// NewStatic returns a provider serving fixed material.
func NewStatic(m *Material, name string) *Static { return &Static{Value: m, Name: name} }

// Material implements Provider.
func (s *Static) Material(_ context.Context, _ Request) (*Material, error) {
	if s == nil || s.Value == nil {
		return nil, ErrUnavailable
	}

	return s.Value, nil
}

// Describe implements Provider.
func (s *Static) Describe() string {
	if s == nil || s.Name == "" {
		return "preloaded trust material"
	}

	return s.Name
}

// Chain tries several providers in order and returns the first that answers.
//
// It is how a caller expresses a preference without giving up a fallback: read
// a local snapshot first, reach for the network only if there is nothing to
// read.
type Chain struct {
	Providers []Provider
}

// NewChain returns a provider trying each of the given providers in order.
func NewChain(providers ...Provider) *Chain {
	return &Chain{Providers: providers}
}

// Material implements Provider.
func (c *Chain) Material(ctx context.Context, req Request) (*Material, error) {
	if c == nil || len(c.Providers) == 0 {
		return nil, ErrUnavailable
	}

	var errs []error

	for _, p := range c.Providers {
		if p == nil {
			continue
		}

		m, err := p.Material(ctx, req)
		if err == nil && m != nil {
			return m, nil
		}

		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p.Describe(), err))
		}
	}

	if len(errs) == 0 {
		return nil, ErrUnavailable
	}

	return nil, errors.Join(append([]error{ErrUnavailable}, errs...)...)
}

// Describe implements Provider.
func (c *Chain) Describe() string {
	if c == nil || len(c.Providers) == 0 {
		return "no trust material provider"
	}

	names := make([]string, 0, len(c.Providers))
	for _, p := range c.Providers {
		if p != nil {
			names = append(names, p.Describe())
		}
	}

	return strings.Join(names, " then ")
}

// Digest returns the SHA-256 of some material, as the lowercase hexadecimal
// string used to identify it.
func Digest(data []byte) string {
	sum := sha256.Sum256(data)

	return hex.EncodeToString(sum[:])
}

// CheckDigest reports whether material matches a declared digest.
func CheckDigest(data []byte, expected string) error {
	if expected == "" {
		return nil
	}

	if got := Digest(data); got != expected {
		return fmt.Errorf("%w: expected %s, got %s", ErrDigestMismatch, expected, got)
	}

	return nil
}

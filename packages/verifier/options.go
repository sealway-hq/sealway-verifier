// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package verifier

import (
	"crypto/x509"
	"net/http"
	"time"

	"github.com/sealway-hq/sealway-verifier/packages/verifier/anchor"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/anchor/algorand"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/anchor/evm"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/bundle"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/pdf"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/proof"
)

// DefaultNetworkTimeout bounds a single blockchain lookup. Network operations
// always run under a deadline so that verification can never hang.
const DefaultNetworkTimeout = 15 * time.Second

// Stage names reported through a ProgressFunc.
const (
	StageCertificate = "certificate"
	StageSources     = "sources"
	StageMerkle      = "proof_merkle"
	StageTimestamp   = "timestamp"
	StageAccumulator = "accumulator"
	StageAnchors     = "anchors"
)

// Progress describes where a verification run currently is.
type Progress struct {
	// Stage is one of the Stage constants.
	Stage string
	// Item names what is being processed, when applicable.
	Item string
	// Current and Total count the work of the stage. Total is zero when the
	// amount of work is not known in advance.
	Current int
	Total   int
}

// ProgressFunc receives progress notifications. It must be safe to call from the
// goroutine running the verification and must not block.
type ProgressFunc func(Progress)

// Limits bounds the resources an untrusted proof can consume.
type Limits struct {
	// Bundle bounds the proof bundle archive.
	Bundle bundle.Limits
	// PDF bounds the certificate and its embedded artifacts.
	PDF pdf.Limits
	// MaxManifestSize bounds the embedded proof manifest.
	MaxManifestSize int64
}

// options carries the resolved configuration of a Verifier.
type options struct {
	verifyBlockchain bool
	httpClient       *http.Client
	networkTimeout   time.Duration
	anchorEndpoints  map[string]string
	anchorRegistry   anchor.Registry
	timestampRoots   *x509.CertPool
	limits           Limits
	progress         ProgressFunc
}

// Option configures a Verifier.
type Option func(*options)

// WithOffline disables every network operation.
//
// Local cryptographic verification is unaffected: only the blockchain anchor
// checks become skipped, with an explicit reason, and the global result becomes
// partial rather than complete.
func WithOffline() Option {
	return func(o *options) { o.verifyBlockchain = false }
}

// WithBlockchainVerification enables or disables the blockchain anchor checks.
func WithBlockchainVerification(enabled bool) Option {
	return func(o *options) { o.verifyBlockchain = enabled }
}

// WithHTTPClient injects the HTTP client used for the public blockchain
// endpoints.
//
// Injecting the client is what makes the anchor providers testable without a
// live network and what lets a browser build supply its own transport.
func WithHTTPClient(c *http.Client) Option {
	return func(o *options) {
		if c != nil {
			o.httpClient = c
		}
	}
}

// WithNetworkTimeout bounds a single blockchain lookup.
func WithNetworkTimeout(d time.Duration) Option {
	return func(o *options) {
		if d > 0 {
			o.networkTimeout = d
		}
	}
}

// WithAnchorEndpoint overrides the public endpoint used for one network.
//
// Endpoints are configurable so that no third party infrastructure is baked into
// the verifier and so that an operator can point it at their own public node.
func WithAnchorEndpoint(network, endpoint string) Option {
	return func(o *options) {
		if network == "" || endpoint == "" {
			return
		}

		if o.anchorEndpoints == nil {
			o.anchorEndpoints = make(map[string]string)
		}

		o.anchorEndpoints[network] = endpoint
	}
}

// WithAnchorVerifier registers a custom verifier for one network, replacing the
// built-in provider.
func WithAnchorVerifier(v anchor.Verifier) Option {
	return func(o *options) {
		if v == nil {
			return
		}

		if o.anchorRegistry == nil {
			o.anchorRegistry = make(anchor.Registry)
		}

		o.anchorRegistry[v.Network()] = v
	}
}

// WithAnchorRegistry replaces the whole set of anchor providers.
func WithAnchorRegistry(r anchor.Registry) Option {
	return func(o *options) { o.anchorRegistry = r }
}

// WithTimestampRoots supplies the trust anchors used to validate the timestamp
// signer certificate chain.
//
// The verifier ships no trust store of its own: deciding which roots to trust is
// a policy decision that belongs to the caller. Without this option the chain
// validation step is reported as skipped rather than assumed to succeed.
func WithTimestampRoots(pool *x509.CertPool) Option {
	return func(o *options) { o.timestampRoots = pool }
}

// WithLimits overrides the resource limits applied to untrusted input.
func WithLimits(l Limits) Option {
	return func(o *options) { o.limits = l }
}

// WithProgress registers a progress callback.
func WithProgress(f ProgressFunc) Option {
	return func(o *options) { o.progress = f }
}

func newOptions(opts ...Option) *options {
	o := &options{
		verifyBlockchain: true,
		networkTimeout:   DefaultNetworkTimeout,
		limits: Limits{
			MaxManifestSize: proof.DefaultMaxManifestSize,
		},
	}

	for _, opt := range opts {
		if opt != nil {
			opt(o)
		}
	}

	if o.httpClient == nil {
		o.httpClient = &http.Client{Timeout: o.networkTimeout}
	}

	if o.limits.MaxManifestSize <= 0 {
		o.limits.MaxManifestSize = proof.DefaultMaxManifestSize
	}

	if o.anchorRegistry == nil {
		o.anchorRegistry = defaultRegistry(o.httpClient, o.anchorEndpoints)
	}

	return o
}

// defaultRegistry returns the built-in providers for the public networks a
// Sealway proof is currently anchored on.
func defaultRegistry(client anchor.HTTPClient, endpoints map[string]string) anchor.Registry {
	return anchor.Registry{
		algorand.Network:   algorand.New(endpoints[algorand.Network], client),
		evm.NetworkPolygon: evm.NewPolygon(endpoints[evm.NetworkPolygon], client),
		evm.NetworkBase:    evm.NewBase(endpoints[evm.NetworkBase], client),
	}
}

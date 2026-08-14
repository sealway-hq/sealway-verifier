// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package trust

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sealway-hq/sealway-verifier/packages/verifier/trust/bootstrap"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/trustlist"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/trustlist/xmldsig"
)

// Default bounds for fetching trust material.
const (
	// DefaultMaxDocumentSize bounds a single fetched document. National lists
	// run to a few megabytes.
	DefaultMaxDocumentSize = 64 << 20 // 64 MiB
	// DefaultTimeout bounds the whole retrieval.
	DefaultTimeout = 30 * time.Second
	// MaxRedirects bounds how far a fetch will follow.
	MaxRedirects = 5
)

// Doer is the subset of net/http a fetcher needs. Taking it as an interface is
// what lets a browser build supply its own transport.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Fetcher retrieves trust material over HTTP.
//
// It starts from the list of lists, authenticates it against the bootstrap
// anchor, and follows only the pointer for the territory it needs. Nothing is
// fetched that the authenticated list did not point at, so a document can never
// send the fetcher somewhere of its own choosing.
type Fetcher struct {
	client Doer
	// lotlURL is where the list of lists is published. A mirror serving the same
	// documents can be substituted here.
	lotlURL string
	// listURL, when set, overrides where a national list is read from, which is
	// how a browser reads through a mirror while still verifying the official
	// signatures. The placeholder {territory} is replaced by the scheme
	// territory.
	listURL string
	// signers are the certificates accepted as signers of the list of lists.
	signers []*x509.Certificate

	maxSize int64
}

// FetcherOption configures a Fetcher.
type FetcherOption func(*Fetcher)

// WithLOTLURL overrides where the list of lists is read from.
//
// The document read there must still be the official signed list: it is
// verified against the bootstrap anchor whatever its origin.
func WithLOTLURL(u string) FetcherOption {
	return func(f *Fetcher) {
		if u != "" {
			f.lotlURL = u
		}
	}
}

// WithListURLTemplate overrides where national lists are read from, replacing
// {territory} with the scheme territory.
//
// The document read there must still be the official signed list, verified
// against the certificates the list of lists pins for that territory.
func WithListURLTemplate(t string) FetcherOption {
	return func(f *Fetcher) {
		if t != "" {
			f.listURL = t
		}
	}
}

// WithSigners overrides the certificates accepted as signers of the list of
// lists.
func WithSigners(certs []*x509.Certificate) FetcherOption {
	return func(f *Fetcher) {
		if len(certs) > 0 {
			f.signers = certs
		}
	}
}

// WithMaxDocumentSize bounds a single fetched document.
func WithMaxDocumentSize(n int64) FetcherOption {
	return func(f *Fetcher) {
		if n > 0 {
			f.maxSize = n
		}
	}
}

// NewFetcher returns a Fetcher using the official publication by default.
func NewFetcher(client Doer, opts ...FetcherOption) (*Fetcher, error) {
	signers, err := bootstrap.LOTLSigners()
	if err != nil {
		return nil, err
	}

	f := &Fetcher{
		client:  client,
		lotlURL: bootstrap.LOTLLocation,
		signers: signers,
		maxSize: DefaultMaxDocumentSize,
	}

	for _, o := range opts {
		if o != nil {
			o(f)
		}
	}

	if f.client == nil {
		return nil, errors.New("trust: no HTTP client was supplied")
	}

	return f, nil
}

// Describe implements Provider.
func (f *Fetcher) Describe() string {
	if f == nil {
		return "no trust material provider"
	}

	return "the European Trusted Lists at " + f.lotlURL
}

// Material implements Provider.
//
// The list of lists is fetched and authenticated first; only then is its pointer
// for the requested territory followed. A territory that the authenticated list
// does not point at is not fetched at all.
func (f *Fetcher) Material(ctx context.Context, req Request) (*Material, error) {
	if req.Offline {
		return nil, fmt.Errorf("%w: network access is disabled", ErrUnavailable)
	}

	lotlRaw, err := f.fetch(ctx, f.lotlURL)
	if err != nil {
		return nil, err
	}

	// Authenticate before reading: the pointer that decides where to go next
	// must come from a document whose signature has been checked.
	verified, err := xmldsig.Verify(lotlRaw, f.signers, xmldsig.Limits{MaxBytes: f.maxSize})
	if err != nil {
		return nil, fmt.Errorf("trust: the list of lists is not authentic: %w", err)
	}

	lotl, err := trustlist.Parse(verified)
	if err != nil {
		return nil, fmt.Errorf("trust: the list of lists is unusable: %w", err)
	}

	material := &Material{
		LOTL:        lotlRaw,
		Lists:       map[string][]byte{},
		Source:      f.Describe(),
		RetrievedAt: time.Now().UTC(),
	}

	territory := strings.ToUpper(strings.TrimSpace(req.Territory))
	if territory == "" {
		return material, nil
	}

	pointer, ok := lotl.PointerFor(territory)
	if !ok {
		return nil, fmt.Errorf("%w: the list of lists carries no machine readable pointer for %s",
			ErrUnavailable, territory)
	}

	location := pointer.Location
	if f.listURL != "" {
		location = strings.ReplaceAll(f.listURL, "{territory}", strings.ToLower(territory))
	}

	listRaw, err := f.fetch(ctx, location)
	if err != nil {
		return nil, err
	}

	material.Lists[territory] = listRaw

	return material, nil
}

// fetch retrieves one document under the configured bounds.
//
// Only HTTPS is accepted, and only for a host that is not a local or otherwise
// internal address, so that neither a pointer nor a configured override can turn
// the verifier into a probe of the network it runs on.
func (f *Fetcher) fetch(ctx context.Context, raw string) ([]byte, error) {
	if err := checkURL(raw); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, fmt.Errorf("trust: cannot build a request for %s: %w", raw, err)
	}

	req.Header.Set("Accept", "application/xml, text/xml, application/octet-stream")
	req.Header.Set("User-Agent", "sealway-verifier")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %s is unreachable: %w", ErrUnavailable, raw, err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %s answered with HTTP %d", ErrUnavailable, raw, resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, f.maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read %s: %w", ErrUnavailable, raw, err)
	}

	if int64(len(data)) > f.maxSize {
		return nil, fmt.Errorf("trust: %s is larger than the %d byte limit", raw, f.maxSize)
	}

	return data, nil
}

// checkURL refuses anything that is not a plain remote HTTPS resource.
func checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("trust: %q is not a usable location: %w", raw, err)
	}

	// Plain HTTP is allowed only for a loopback host, which is what a test
	// server is; everything reachable off the machine must be HTTPS.
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return fmt.Errorf("trust: %q must use HTTPS", raw)
		}

		return nil
	default:
		return fmt.Errorf("trust: %q uses the unsupported scheme %q", raw, u.Scheme)
	}

	if isInternalHost(u.Hostname()) {
		return fmt.Errorf("trust: %q points at an internal address", raw)
	}

	return nil
}

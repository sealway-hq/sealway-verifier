// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package trust_test

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealway-hq/sealway-verifier/internal/prooftest"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/trust"
)

// scheme builds a throwaway European scheme and the documents it publishes.
func scheme(t *testing.T) (s *prooftest.TrustScheme, lotl, list []byte) {
	t.Helper()

	s, err := prooftest.NewTrustScheme("ES")
	require.NoError(t, err)

	lotl, err = s.LOTL(prooftest.LOTLOptions{})
	require.NoError(t, err)

	list, err = s.TrustList(prooftest.TrustListOptions{
		Services: []prooftest.TrustService{{
			ProviderName: "Test Trust Services",
			ServiceName:  "Qualified electronic time stamps",
			Status:       prooftest.StatusGranted,
		}},
	})
	require.NoError(t, err)

	return s, lotl, list
}

func snapshotFS(t *testing.T, lotl, list []byte) fstest.MapFS {
	t.Helper()

	files, err := prooftest.SnapshotFiles(lotl, map[string][]byte{"ES": list})
	require.NoError(t, err)

	out := fstest.MapFS{}
	for name, data := range files {
		out[name] = &fstest.MapFile{Data: data}
	}

	return out
}

func TestSnapshotServesStoredMaterial(t *testing.T) {
	t.Parallel()

	_, lotl, list := scheme(t)

	p := trust.NewSnapshot(snapshotFS(t, lotl, list), "test")
	assert.Contains(t, p.Describe(), "test")

	m, err := p.Material(t.Context(), trust.Request{Territory: "ES"})
	require.NoError(t, err)

	assert.Equal(t, lotl, m.LOTL)
	assert.Equal(t, list, m.Lists["ES"])
	assert.Equal(t, []string{"ES"}, m.Territories())
}

// TestSnapshotDetectsAlteredBytes is what makes a mirror or a cache unable to
// substitute material without being noticed.
func TestSnapshotDetectsAlteredBytes(t *testing.T) {
	t.Parallel()

	_, lotl, list := scheme(t)

	fsys := snapshotFS(t, lotl, list)
	fsys["lists/es.xml"] = &fstest.MapFile{Data: append(list, ' ')}

	_, err := trust.NewSnapshot(fsys, "tampered").
		Material(t.Context(), trust.Request{Territory: "ES"})
	assert.ErrorIs(t, err, trust.ErrDigestMismatch)
}

func TestSnapshotRejectsUnusableManifests(t *testing.T) {
	t.Parallel()

	_, lotl, list := scheme(t)

	t.Run("unsupported format", func(t *testing.T) {
		t.Parallel()

		fsys := snapshotFS(t, lotl, list)
		fsys["manifest.json"] = &fstest.MapFile{Data: []byte(`{"format":"something-else/9"}`)}

		_, err := trust.NewSnapshot(fsys, "x").Material(t.Context(), trust.Request{})
		assert.ErrorIs(t, err, trust.ErrUnsupportedSnapshot)
	})

	t.Run("not json", func(t *testing.T) {
		t.Parallel()

		fsys := snapshotFS(t, lotl, list)
		fsys["manifest.json"] = &fstest.MapFile{Data: []byte("not json")}

		_, err := trust.NewSnapshot(fsys, "x").Material(t.Context(), trust.Request{})
		assert.Error(t, err)
	})

	t.Run("escaping path", func(t *testing.T) {
		t.Parallel()

		fsys := snapshotFS(t, lotl, list)
		fsys["manifest.json"] = &fstest.MapFile{Data: []byte(
			`{"format":"sealway-trust-snapshot/1","lotl":{"path":"../../etc/passwd"}}`)}

		_, err := trust.NewSnapshot(fsys, "x").Material(t.Context(), trust.Request{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a plain relative path")
	})

	t.Run("missing manifest", func(t *testing.T) {
		t.Parallel()

		_, err := trust.NewSnapshot(fstest.MapFS{}, "x").Material(t.Context(), trust.Request{})
		assert.ErrorIs(t, err, trust.ErrUnavailable)
	})

	t.Run("territory absent", func(t *testing.T) {
		t.Parallel()

		_, err := trust.NewSnapshot(snapshotFS(t, lotl, list), "x").
			Material(t.Context(), trust.Request{Territory: "FR"})
		assert.ErrorIs(t, err, trust.ErrUnavailable)
	})
}

func TestBuildManifestDescribesMaterial(t *testing.T) {
	t.Parallel()

	_, lotl, list := scheme(t)

	m := &trust.Material{LOTL: lotl, Lists: map[string][]byte{"ES": list}}

	manifest := trust.BuildManifest(m, map[string]string{"lotl": "https://example.test/lotl.xml"},
		time.Date(2026, time.August, 15, 0, 0, 0, 0, time.UTC))

	assert.Equal(t, trust.SnapshotFormat, manifest.Format)
	assert.Equal(t, "lotl.xml", manifest.LOTL.Path)
	assert.Equal(t, trust.Digest(lotl), manifest.LOTL.SHA256)
	assert.Equal(t, int64(len(lotl)), manifest.LOTL.Size)

	es := manifest.Lists["ES"]
	assert.Equal(t, "lists/es.xml", es.Path)
	assert.Equal(t, trust.Digest(list), es.SHA256)
	assert.Equal(t, "ES", es.Territory)
}

func TestStaticProvider(t *testing.T) {
	t.Parallel()

	m := &trust.Material{LOTL: []byte("x")}

	p := trust.NewStatic(m, "preloaded")
	assert.Equal(t, "preloaded", p.Describe())

	got, err := p.Material(t.Context(), trust.Request{})
	require.NoError(t, err)
	assert.Equal(t, m, got)

	_, err = trust.NewStatic(nil, "").Material(t.Context(), trust.Request{})
	assert.ErrorIs(t, err, trust.ErrUnavailable)
	assert.Equal(t, "preloaded trust material", trust.NewStatic(nil, "").Describe())
}

// TestChainFallsBackInOrder covers reading a local snapshot first and reaching
// for the network only when there is nothing to read.
func TestChainFallsBackInOrder(t *testing.T) {
	t.Parallel()

	wanted := &trust.Material{LOTL: []byte("second")}

	c := trust.NewChain(
		trust.NewStatic(nil, "empty"),
		trust.NewStatic(wanted, "populated"),
	)

	got, err := c.Material(t.Context(), trust.Request{})
	require.NoError(t, err)
	assert.Equal(t, wanted, got)

	assert.Contains(t, c.Describe(), "empty then populated")

	_, err = trust.NewChain().Material(t.Context(), trust.Request{})
	assert.ErrorIs(t, err, trust.ErrUnavailable)

	_, err = trust.NewChain(trust.NewStatic(nil, "a"), trust.NewStatic(nil, "b")).
		Material(t.Context(), trust.Request{})
	assert.ErrorIs(t, err, trust.ErrUnavailable)
}

func TestCheckDigest(t *testing.T) {
	t.Parallel()

	data := []byte("payload")

	assert.NoError(t, trust.CheckDigest(data, trust.Digest(data)))
	assert.NoError(t, trust.CheckDigest(data, ""), "an absent digest is not a mismatch")
	assert.ErrorIs(t, trust.CheckDigest(data, trust.Digest([]byte("other"))), trust.ErrDigestMismatch)
}

// mirror serves the given documents, standing in for the official publications.
func mirror(t *testing.T, lotl, list []byte) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/lotl.xml", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(lotl) })
	mux.HandleFunc("/lists/es.xml", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(list) })

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return srv
}

func TestFetcherAuthenticatesBeforeFollowingAPointer(t *testing.T) {
	t.Parallel()

	s, lotl, list := scheme(t)
	srv := mirror(t, lotl, list)

	f, err := trust.NewFetcher(srv.Client(),
		trust.WithLOTLURL(srv.URL+"/lotl.xml"),
		trust.WithListURLTemplate(srv.URL+"/lists/{territory}.xml"),
		trust.WithSigners(certsOf(s)),
	)
	require.NoError(t, err)

	m, err := f.Material(t.Context(), trust.Request{Territory: "ES"})
	require.NoError(t, err)

	assert.Equal(t, lotl, m.LOTL)
	assert.Equal(t, list, m.Lists["ES"])
	assert.Contains(t, f.Describe(), srv.URL)
}

// TestFetcherRefusesAnUnauthenticListOfLists is the decisive property: the
// pointer that decides where to go next must come from a document whose
// signature verified.
func TestFetcherRefusesAnUnauthenticListOfLists(t *testing.T) {
	t.Parallel()

	s, _, list := scheme(t)

	forged, err := s.LOTL(prooftest.LOTLOptions{CorruptSignature: true})
	require.NoError(t, err)

	srv := mirror(t, forged, list)

	f, err := trust.NewFetcher(srv.Client(),
		trust.WithLOTLURL(srv.URL+"/lotl.xml"),
		trust.WithSigners(certsOf(s)),
	)
	require.NoError(t, err)

	_, err = f.Material(t.Context(), trust.Request{Territory: "ES"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not authentic")
}

func TestFetcherRespectsOffline(t *testing.T) {
	t.Parallel()

	s, lotl, list := scheme(t)

	called := false

	mux := http.NewServeMux()
	mux.HandleFunc("/lotl.xml", func(w http.ResponseWriter, _ *http.Request) {
		called = true
		_, _ = w.Write(lotl)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	_ = list

	f, err := trust.NewFetcher(srv.Client(),
		trust.WithLOTLURL(srv.URL+"/lotl.xml"),
		trust.WithSigners(certsOf(s)),
	)
	require.NoError(t, err)

	_, err = f.Material(t.Context(), trust.Request{Territory: "ES", Offline: true})
	assert.ErrorIs(t, err, trust.ErrUnavailable)
	assert.False(t, called, "offline must prevent the request, not just discard its result")
}

func TestFetcherReportsAnUnknownTerritory(t *testing.T) {
	t.Parallel()

	s, lotl, list := scheme(t)
	srv := mirror(t, lotl, list)

	f, err := trust.NewFetcher(srv.Client(),
		trust.WithLOTLURL(srv.URL+"/lotl.xml"),
		trust.WithSigners(certsOf(s)),
	)
	require.NoError(t, err)

	_, err = f.Material(t.Context(), trust.Request{Territory: "ZZ"})
	require.ErrorIs(t, err, trust.ErrUnavailable)
	assert.Contains(t, err.Error(), "no machine readable pointer")
}

func TestFetcherEnforcesDocumentSize(t *testing.T) {
	t.Parallel()

	s, lotl, list := scheme(t)
	srv := mirror(t, lotl, list)

	f, err := trust.NewFetcher(srv.Client(),
		trust.WithLOTLURL(srv.URL+"/lotl.xml"),
		trust.WithSigners(certsOf(s)),
		trust.WithMaxDocumentSize(16),
	)
	require.NoError(t, err)

	_, err = f.Material(t.Context(), trust.Request{Territory: "ES"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "larger than")
}

func TestFetcherReportsAnUnreachableSource(t *testing.T) {
	t.Parallel()

	f, err := trust.NewFetcher(&http.Client{Timeout: time.Second},
		trust.WithLOTLURL("http://127.0.0.1:1/lotl.xml"))
	require.NoError(t, err)

	_, err = f.Material(t.Context(), trust.Request{Territory: "ES"})
	assert.ErrorIs(t, err, trust.ErrUnavailable)
}

func TestNewFetcherRequiresAClient(t *testing.T) {
	t.Parallel()

	_, err := trust.NewFetcher(nil)
	assert.Error(t, err)
}

// TestFetcherRefusesLocationsThatPointInwards is the guard that keeps a
// document, or a mistaken configuration, from turning the verifier into a probe
// of the network it runs on.
func TestFetcherRefusesLocationsThatPointInwards(t *testing.T) {
	t.Parallel()

	locations := []string{
		"https://10.0.0.1/lotl.xml",
		"https://192.168.1.1/lotl.xml",
		"https://172.16.0.1/lotl.xml",
		"https://169.254.169.254/latest/meta-data/",
		"https://[fd00::1]/lotl.xml",
		"https://[::1]/lotl.xml",
		"https://100.64.0.1/lotl.xml",
		"https://192.0.2.1/lotl.xml",
		"https://localhost/lotl.xml",
	}

	for _, location := range locations {
		f, err := trust.NewFetcher(http.DefaultClient, trust.WithLOTLURL(location))
		require.NoError(t, err)

		_, err = f.Material(t.Context(), trust.Request{Territory: "ES"})
		require.Error(t, err, "location %s must be refused", location)
		assert.Contains(t, err.Error(), "internal address", "location %s", location)
	}
}

// TestFetcherRefusesUnsupportedSchemes keeps a location from reaching anything
// other than a published document.
func TestFetcherRefusesUnsupportedSchemes(t *testing.T) {
	t.Parallel()

	for _, location := range []string{
		"file:///etc/passwd",
		"ftp://example.test/lotl.xml",
		"gopher://example.test/",
		"data:text/xml,<a/>",
	} {
		f, err := trust.NewFetcher(http.DefaultClient, trust.WithLOTLURL(location))
		require.NoError(t, err)

		_, err = f.Material(t.Context(), trust.Request{Territory: "ES"})
		require.Error(t, err, "location %s must be refused", location)
		assert.Contains(t, err.Error(), "unsupported scheme", "location %s", location)
	}
}

// TestFetcherRefusesPlainHTTPOffTheMachine keeps published material on a
// transport that cannot be rewritten in flight.
func TestFetcherRefusesPlainHTTPOffTheMachine(t *testing.T) {
	t.Parallel()

	f, err := trust.NewFetcher(http.DefaultClient,
		trust.WithLOTLURL("http://example.test/lotl.xml"))
	require.NoError(t, err)

	_, err = f.Material(t.Context(), trust.Request{Territory: "ES"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must use HTTPS")
}

func TestFetcherReportsAnErrorStatus(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	f, err := trust.NewFetcher(srv.Client(), trust.WithLOTLURL(srv.URL+"/lotl.xml"))
	require.NoError(t, err)

	_, err = f.Material(t.Context(), trust.Request{Territory: "ES"})
	require.ErrorIs(t, err, trust.ErrUnavailable)
	assert.Contains(t, err.Error(), "503")
}

func TestFetcherHonoursACancelledContext(t *testing.T) {
	t.Parallel()

	s, lotl, list := scheme(t)
	srv := mirror(t, lotl, list)

	f, err := trust.NewFetcher(srv.Client(),
		trust.WithLOTLURL(srv.URL+"/lotl.xml"),
		trust.WithSigners(certsOf(s)),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err = f.Material(ctx, trust.Request{Territory: "ES"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled) || errors.Is(err, trust.ErrUnavailable))
}

func TestNilMaterialTerritories(t *testing.T) {
	t.Parallel()

	var m *trust.Material

	assert.Nil(t, m.Territories())
}

func certsOf(s *prooftest.TrustScheme) []*x509.Certificate {
	return []*x509.Certificate{s.LOTLSigner.Certificate}
}

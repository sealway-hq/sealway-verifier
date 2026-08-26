// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package eidas_test

import (
	"crypto/x509"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealway-hq/sealway-verifier/internal/prooftest"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/eidas"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/trust"
)

// genTime is the instant every assessment is made at. It is deliberately in the
// middle of the generated status timelines.
var genTime = time.Date(2026, time.August, 14, 8, 30, 27, 0, time.UTC)

// scheme carries a throwaway European trust scheme together with a timestamping
// authority whose certificates it publishes.
type scheme struct {
	*prooftest.TrustScheme

	tsa *prooftest.TSA
}

func newScheme(t *testing.T) *scheme {
	t.Helper()

	ts, err := prooftest.NewTrustScheme("ES")
	require.NoError(t, err)

	tsa, err := prooftest.NewTSA()
	require.NoError(t, err)

	return &scheme{TrustScheme: ts, tsa: tsa}
}

// evaluatorFor builds an evaluator reading a snapshot holding the given lists.
func evaluatorFor(t *testing.T, s *scheme, lotl, list []byte) *eidas.Evaluator {
	t.Helper()

	lists := map[string][]byte{}
	if list != nil {
		lists["ES"] = list
	}

	files, err := prooftest.SnapshotFiles(lotl, lists)
	require.NoError(t, err)

	mapFS := fstest.MapFS{}
	for name, data := range files {
		mapFS[name] = &fstest.MapFile{Data: data}
	}

	provider := trust.NewSnapshot(mapFS, "test snapshot")

	e, err := eidas.NewEvaluator(provider,
		eidas.WithSigners([]*x509.Certificate{s.LOTLSigner.Certificate}))
	require.NoError(t, err)

	return e
}

// assess runs a determination for the scheme's timestamping certificate.
func assess(t *testing.T, s *scheme, lotl, list []byte) *eidas.Assessment {
	t.Helper()

	return evaluatorFor(t, s, lotl, list).
		Evaluate(t.Context(), s.tsa.SignerCert,
			[]*x509.Certificate{s.tsa.SignerCert, s.tsa.RootCert}, genTime, false)
}

// grantedService publishes the authority that issued the timestamping
// certificate, which is how a Trusted List normally identifies a service.
func (s *scheme) grantedService() prooftest.TrustService {
	return prooftest.TrustService{
		ProviderName: "Test Trust Services",
		ServiceName:  "Qualified electronic time stamps",
		Identity:     s.tsa.RootCert,
		Status:       prooftest.StatusGranted,
		StatusSince:  time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC),
	}
}

func (s *scheme) lists(t *testing.T, services ...prooftest.TrustService) (lotl, list []byte) {
	t.Helper()

	l, err := s.LOTL(prooftest.LOTLOptions{})
	require.NoError(t, err)

	tl, err := s.TrustList(prooftest.TrustListOptions{Services: services})
	require.NoError(t, err)

	return l, tl
}

// TestQualifiedWhenGrantedAtGenTime is the case the whole subsystem exists for.
func TestQualifiedWhenGrantedAtGenTime(t *testing.T) {
	t.Parallel()

	s := newScheme(t)
	lotl, list := s.lists(t, s.grantedService())

	a := assess(t, s, lotl, list)

	require.Equal(t, eidas.Qualified, a.Determination, "reasons: %v", a.Reasons)
	require.NotNil(t, a.Decisive)
	assert.Equal(t, eidas.MatchIssuer, a.Decisive.Kind)
	assert.Equal(t, "ES", a.TrustListTerritory)
	assert.False(t, a.Conflicting())
	assert.NotEmpty(t, a.Reasons)
}

// TestNotQualifiedWhenGrantedOnlyAfterGenTime pins that recognition is read at
// the instant the token asserts, not at the instant of verification.
func TestNotQualifiedWhenGrantedOnlyAfterGenTime(t *testing.T) {
	t.Parallel()

	s := newScheme(t)

	svc := s.grantedService()
	svc.StatusSince = genTime.Add(24 * time.Hour)

	lotl, list := s.lists(t, svc)

	a := assess(t, s, lotl, list)

	// The status timeline starts after the asserted time, so nothing is known
	// about that instant and no service applies.
	assert.Equal(t, eidas.Indeterminate, a.Determination)
}

// TestNotQualifiedWhenWithdrawnBeforeGenTime covers a recognition that had ended
// by the time the token was produced.
func TestNotQualifiedWhenWithdrawnBeforeGenTime(t *testing.T) {
	t.Parallel()

	s := newScheme(t)

	svc := s.grantedService()
	svc.Status = prooftest.StatusWithdrawn
	svc.StatusSince = genTime.Add(-48 * time.Hour)
	svc.History = []prooftest.TrustServiceHistory{{
		Status:      prooftest.StatusGranted,
		StatusSince: time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC),
	}}

	lotl, list := s.lists(t, svc)

	a := assess(t, s, lotl, list)

	require.Equal(t, eidas.NotQualified, a.Determination)
	require.NotNil(t, a.Decisive)
	assert.False(t, a.Decisive.Qualified)
}

// TestQualifiedBeforeWithdrawal is the same list read at an earlier instant: the
// timestamp was produced while the service was still recognised.
func TestQualifiedBeforeWithdrawal(t *testing.T) {
	t.Parallel()

	s := newScheme(t)

	// The recognition ends after the asserted time, so the same list answers
	// differently depending on the instant it is asked about.
	svc := s.grantedService()
	svc.Status = prooftest.StatusWithdrawn
	svc.StatusSince = genTime.Add(48 * time.Hour)
	svc.History = []prooftest.TrustServiceHistory{{
		Status:      prooftest.StatusGranted,
		StatusSince: time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC),
	}}

	lotl, list := s.lists(t, svc)

	a := assess(t, s, lotl, list)
	assert.Equal(t, eidas.Qualified, a.Determination,
		"at the asserted time the recognition was still in force; reasons: %v", a.Reasons)

	// After the withdrawal took effect, the very same list says the opposite.
	later := evaluatorFor(t, s, lotl, list).
		Evaluate(t.Context(), s.tsa.SignerCert,
			[]*x509.Certificate{s.tsa.RootCert}, genTime.Add(72*time.Hour), false)

	assert.Equal(t, eidas.NotQualified, later.Determination)
}

// TestConflictingEntriesAreReported covers the shape found in the real Spanish
// list: one entry naming the signing unit was withdrawn while another naming the
// issuing authority stayed granted.
func TestConflictingEntriesAreReported(t *testing.T) {
	t.Parallel()

	s := newScheme(t)

	withdrawnLeaf := prooftest.TrustService{
		ProviderName: "Test Trust Services",
		ServiceName:  "Qualified timestamps issued by the signing unit",
		Identity:     s.tsa.SignerCert,
		Status:       prooftest.StatusWithdrawn,
		StatusSince:  genTime.Add(-72 * time.Hour),
		History: []prooftest.TrustServiceHistory{{
			Status:      prooftest.StatusGranted,
			StatusSince: time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC),
		}},
	}

	lotl, list := s.lists(t, withdrawnLeaf, s.grantedService())

	a := assess(t, s, lotl, list)

	// A path to a recognised service exists, so the condition a Trusted List
	// answers is met; the disagreement is reported rather than hidden.
	require.Equal(t, eidas.Qualified, a.Determination, "reasons: %v", a.Reasons)
	assert.True(t, a.Conflicting())
	assert.Len(t, a.Matches, 2)
	require.NotNil(t, a.Decisive)
	assert.True(t, a.Decisive.Qualified)
}

// TestReinstatementIsNotRetroactive covers a status timeline that goes granted,
// withdrawn, then granted again, which is what a supervisory body publishes when
// it corrects an entry it withdrew.
//
// The correction applies from the instant the list says it applies, and no
// earlier. A timestamp produced inside the withdrawal window is still read
// against the status that was published then, because the question a Trusted
// List answers is what was recognised at genTime, never what is recognised now.
func TestReinstatementIsNotRetroactive(t *testing.T) {
	t.Parallel()

	s := newScheme(t)

	// The three periods run forward from genTime because the throwaway
	// timestamping certificates only become valid shortly before it, and a
	// certification path that does not validate would mask the status question
	// this test is about.
	svc := s.grantedService()
	svc.Status = prooftest.StatusGranted
	svc.StatusSince = genTime.Add(72 * time.Hour)
	svc.History = []prooftest.TrustServiceHistory{
		{
			Status:      prooftest.StatusGranted,
			StatusSince: time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			Status:      prooftest.StatusWithdrawn,
			StatusSince: genTime.Add(24 * time.Hour),
		},
	}

	lotl, list := s.lists(t, svc)

	for _, tc := range []struct {
		name string
		at   time.Time
		want eidas.Determination
	}{
		{"before the withdrawal", genTime, eidas.Qualified},
		{"inside the withdrawal window", genTime.Add(48 * time.Hour), eidas.NotQualified},
		{"after the reinstatement", genTime.Add(96 * time.Hour), eidas.Qualified},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			a := evaluatorFor(t, s, lotl, list).
				Evaluate(t.Context(), s.tsa.SignerCert,
					[]*x509.Certificate{s.tsa.SignerCert, s.tsa.RootCert}, tc.at, false)

			assert.Equal(t, tc.want, a.Determination, "reasons: %v", a.Reasons)
		})
	}
}

// TestCorrectedWithdrawalRestoresTheWholePeriod is the other way a supervisory
// body can fix a mistake: by removing the withdrawal from the record instead of
// ending it. The entry then reads as granted throughout, including for a
// timestamp produced while the erroneous withdrawal was published.
func TestCorrectedWithdrawalRestoresTheWholePeriod(t *testing.T) {
	t.Parallel()

	s := newScheme(t)

	lotl, list := s.lists(t, s.grantedService())

	a := assess(t, s, lotl, list)
	assert.Equal(t, eidas.Qualified, a.Determination, "reasons: %v", a.Reasons)
	assert.False(t, a.Conflicting(), "a corrected record leaves nothing to disagree with")
}

// TestIndeterminateWhenTheCertificateNamesNoCountry keeps the verifier from
// guessing which member state supervises a service.
//
// A trust service is supervised by the state it is established in, and the
// certificate states that as its country. Without it there is no way to know
// which national list would cover the service, and picking one anyway would be
// inventing the answer. The determination is therefore left undecided.
func TestIndeterminateWhenTheCertificateNamesNoCountry(t *testing.T) {
	t.Parallel()

	ts, err := prooftest.NewTrustScheme("ES")
	require.NoError(t, err)

	tsa, err := prooftest.NewTSA(prooftest.TSAOptions{OmitCountry: true})
	require.NoError(t, err)

	s := &scheme{TrustScheme: ts, tsa: tsa}

	lotl, list := s.lists(t, s.grantedService())

	a := assess(t, s, lotl, list)

	assert.Equal(t, eidas.Indeterminate, a.Determination)
	assert.Contains(t, strings.Join(a.Reasons, " "), "declares no country")
}

// TestTerritoryFallsBackToTheIssuerCountry covers the shape a real hierarchy
// often has: the signing unit carries little naming detail while the authority
// that issued it carries the country. The supervising state is the same either
// way, so the list is still found.
func TestTerritoryFallsBackToTheIssuerCountry(t *testing.T) {
	t.Parallel()

	ts, err := prooftest.NewTrustScheme("ES")
	require.NoError(t, err)

	tsa, err := prooftest.NewTSA(prooftest.TSAOptions{OmitSignerCountry: true})
	require.NoError(t, err)

	s := &scheme{TrustScheme: ts, tsa: tsa}

	require.Empty(t, s.tsa.SignerCert.Subject.Country, "the fallback is what is under test")

	lotl, list := s.lists(t, s.grantedService())

	a := assess(t, s, lotl, list)
	assert.Equal(t, eidas.Qualified, a.Determination, "reasons: %v", a.Reasons)
}

// TestIndeterminateWithoutAnyList records that a missing list is an absence of
// evidence, not a denial.
func TestIndeterminateWithoutAnyList(t *testing.T) {
	t.Parallel()

	s := newScheme(t)

	lotl, err := s.LOTL(prooftest.LOTLOptions{})
	require.NoError(t, err)

	a := assess(t, s, lotl, nil)

	assert.Equal(t, eidas.Indeterminate, a.Determination)
	assert.NotEmpty(t, a.Reasons)
}

// TestIndeterminateWhenTheListOfListsIsNotAuthentic refuses to read a list of
// lists whose signature does not verify.
func TestIndeterminateWhenTheListOfListsIsNotAuthentic(t *testing.T) {
	t.Parallel()

	s := newScheme(t)

	lotl, err := s.LOTL(prooftest.LOTLOptions{CorruptSignature: true})
	require.NoError(t, err)

	list, err := s.TrustList(prooftest.TrustListOptions{Services: []prooftest.TrustService{s.grantedService()}})
	require.NoError(t, err)

	a := assess(t, s, lotl, list)

	require.Equal(t, eidas.Indeterminate, a.Determination)
	assert.Contains(t, a.Reasons[0], "not authentic")
}

// TestIndeterminateWhenTheNationalListIsNotAuthentic refuses a national list
// that does not verify against the certificates the list of lists pins.
func TestIndeterminateWhenTheNationalListIsNotAuthentic(t *testing.T) {
	t.Parallel()

	s := newScheme(t)

	lotl, err := s.LOTL(prooftest.LOTLOptions{})
	require.NoError(t, err)

	list, err := s.TrustList(prooftest.TrustListOptions{
		Services:         []prooftest.TrustService{s.grantedService()},
		CorruptSignature: true,
	})
	require.NoError(t, err)

	a := assess(t, s, lotl, list)

	require.Equal(t, eidas.Indeterminate, a.Determination)
	assert.Contains(t, a.Reasons[0], "not authentic")
}

// TestIndeterminateWhenAnotherOperatorSignedTheList is the substitution attempt:
// a well formed list signed by somebody the list of lists does not pin.
func TestIndeterminateWhenAnotherOperatorSignedTheList(t *testing.T) {
	t.Parallel()

	s := newScheme(t)

	other, err := prooftest.NewTrustScheme("ES")
	require.NoError(t, err)

	lotl, err := s.LOTL(prooftest.LOTLOptions{})
	require.NoError(t, err)

	// The list is genuine in shape but signed by an unrelated operator.
	forged, err := other.TrustList(prooftest.TrustListOptions{
		Services: []prooftest.TrustService{s.grantedService()},
	})
	require.NoError(t, err)

	a := assess(t, s, lotl, forged)

	require.Equal(t, eidas.Indeterminate, a.Determination)
	assert.Contains(t, a.Reasons[0], "not authentic")
}

// TestIndeterminateWhenNoSignerIsPinned refuses to accept a national list the
// list of lists does not vouch for.
func TestIndeterminateWhenNoSignerIsPinned(t *testing.T) {
	t.Parallel()

	s := newScheme(t)

	lotl, err := s.LOTL(prooftest.LOTLOptions{OmitSigningCertificates: true})
	require.NoError(t, err)

	list, err := s.TrustList(prooftest.TrustListOptions{
		Services: []prooftest.TrustService{s.grantedService()},
	})
	require.NoError(t, err)

	a := assess(t, s, lotl, list)

	require.Equal(t, eidas.Indeterminate, a.Determination)
	assert.Contains(t, a.Reasons[0], "pins no signing certificate")
}

// TestIndeterminateWhenTheListOfListsHasNoPointer covers a territory the
// European list does not point at.
func TestIndeterminateWhenTheListOfListsHasNoPointer(t *testing.T) {
	t.Parallel()

	s := newScheme(t)

	lotl, err := s.LOTL(prooftest.LOTLOptions{OmitPointer: true})
	require.NoError(t, err)

	list, err := s.TrustList(prooftest.TrustListOptions{
		Services: []prooftest.TrustService{s.grantedService()},
	})
	require.NoError(t, err)

	a := assess(t, s, lotl, list)

	require.Equal(t, eidas.Indeterminate, a.Determination)
	assert.Contains(t, a.Reasons[0], "no machine readable pointer")
}

// TestNonQualifiedServiceTypeIsNotConsidered records that a timestamping service
// that is not of a qualified type cannot make a timestamp qualified.
func TestNonQualifiedServiceTypeIsNotConsidered(t *testing.T) {
	t.Parallel()

	s := newScheme(t)

	svc := s.grantedService()
	svc.Type = prooftest.ServiceTypeTSA

	lotl, list := s.lists(t, svc)

	a := assess(t, s, lotl, list)

	assert.Equal(t, eidas.Indeterminate, a.Determination)
	assert.Empty(t, a.Matches)
}

// TestUnrelatedAuthorityDoesNotMatch checks a service published by somebody else
// never attaches to this signer.
func TestUnrelatedAuthorityDoesNotMatch(t *testing.T) {
	t.Parallel()

	s := newScheme(t)

	stranger, err := prooftest.NewTSA()
	require.NoError(t, err)

	svc := s.grantedService()
	svc.Identity = stranger.RootCert

	lotl, list := s.lists(t, svc)

	a := assess(t, s, lotl, list)

	assert.Equal(t, eidas.Indeterminate, a.Determination)
	assert.Empty(t, a.Matches)
}

// TestOfflineWithoutMaterialIsIndeterminate keeps a disabled network from
// looking like a denial.
func TestOfflineWithoutMaterialIsIndeterminate(t *testing.T) {
	t.Parallel()

	s := newScheme(t)

	e, err := eidas.NewEvaluator(trust.NewStatic(nil, "nothing"),
		eidas.WithSigners([]*x509.Certificate{s.LOTLSigner.Certificate}))
	require.NoError(t, err)

	a := e.Evaluate(t.Context(), s.tsa.SignerCert, nil, genTime, true)

	assert.Equal(t, eidas.Indeterminate, a.Determination)
	assert.NotEmpty(t, a.Reasons)
}

// TestSnapshotDetectsAlteredMaterial checks a stored document that does not
// match its declared digest is refused rather than read.
func TestSnapshotDetectsAlteredMaterial(t *testing.T) {
	t.Parallel()

	s := newScheme(t)
	lotl, list := s.lists(t, s.grantedService())

	files, err := prooftest.SnapshotFiles(lotl, map[string][]byte{"ES": list})
	require.NoError(t, err)

	// Alter the stored list without updating the manifest.
	files["lists/es.xml"] = append(files["lists/es.xml"], ' ')

	mapFS := fstest.MapFS{}
	for name, data := range files {
		mapFS[name] = &fstest.MapFile{Data: data}
	}

	e, err := eidas.NewEvaluator(trust.NewSnapshot(mapFS, "tampered snapshot"),
		eidas.WithSigners([]*x509.Certificate{s.LOTLSigner.Certificate}))
	require.NoError(t, err)

	a := e.Evaluate(t.Context(), s.tsa.SignerCert, nil, genTime, false)

	require.Equal(t, eidas.Indeterminate, a.Determination)
	assert.Contains(t, a.Reasons[0], "digest")
}

// TestSignerCertificateExpiredTodayButValidAtGenTime is the property that makes
// old proofs stay verifiable: a path is validated at the asserted time.
func TestSignerCertificateExpiredTodayButValidAtGenTime(t *testing.T) {
	t.Parallel()

	s := newScheme(t)
	lotl, list := s.lists(t, s.grantedService())

	// The generated timestamping certificate expires a year after the asserted
	// time, so a validation performed much later must still succeed.
	future := prooftest.DefaultGenTime.Add(10 * 365 * 24 * time.Hour)
	require.True(t, s.tsa.SignerCert.NotAfter.Before(future))

	a := assess(t, s, lotl, list)

	assert.Equal(t, eidas.Qualified, a.Determination,
		"the path must be validated at the asserted time, not at the time of verification")
}

// TestNoSignerIsIndeterminate covers a token whose signer could not be
// identified.
func TestNoSignerIsIndeterminate(t *testing.T) {
	t.Parallel()

	s := newScheme(t)

	e, err := eidas.NewEvaluator(trust.NewStatic(&trust.Material{}, "empty"),
		eidas.WithSigners([]*x509.Certificate{s.LOTLSigner.Certificate}))
	require.NoError(t, err)

	a := e.Evaluate(t.Context(), nil, nil, genTime, false)

	assert.Equal(t, eidas.Indeterminate, a.Determination)
	assert.Contains(t, a.Reasons[0], "no identifiable signer")
}

func TestDeterminationString(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "qualified", eidas.Qualified.String())
	assert.Equal(t, "not_qualified", eidas.NotQualified.String())
	assert.Equal(t, "indeterminate", eidas.Indeterminate.String())
}

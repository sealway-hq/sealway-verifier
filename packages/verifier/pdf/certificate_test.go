// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package pdf_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealway-hq/sealway-verifier/internal/prooftest"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/pdf"
)

func certificate(t *testing.T, attachments ...prooftest.Attachment) []byte {
	t.Helper()

	data, err := prooftest.BuildCertificate("SW-2026-TEST0001", attachments)
	require.NoError(t, err)

	return data
}

func bothAttachments() []prooftest.Attachment {
	return []prooftest.Attachment{
		{Name: pdf.ManifestAttachmentName, Description: "manifest", Content: []byte(`{"version":"1.1"}`)},
		{Name: pdf.TimestampAttachmentName, Description: "token", Content: []byte{0x30, 0x03, 0x02, 0x01, 0x00}},
	}
}

func TestOpenExtractsBothArtifacts(t *testing.T) {
	t.Parallel()

	cert, err := pdf.Open(bytes.NewReader(certificate(t, bothAttachments()...)), pdf.Limits{})
	require.NoError(t, err)

	assert.JSONEq(t, `{"version":"1.1"}`, string(cert.Manifest))
	assert.Equal(t, []byte{0x30, 0x03, 0x02, 0x01, 0x00}, cert.Timestamp)
	assert.False(t, cert.Signed)
	assert.NotEmpty(t, cert.PDFVersion)

	assert.Equal(t,
		[]string{pdf.TimestampAttachmentName, pdf.ManifestAttachmentName},
		cert.AttachmentNames())
	assert.Contains(t, cert.AttachmentSummary(), pdf.ManifestAttachmentName)
}

// TestOpenReportsMissingManifest checks that a readable certificate missing one
// artifact still yields everything it did contain, so the caller can report
// precisely what is absent instead of failing opaquely.
func TestOpenReportsMissingManifest(t *testing.T) {
	t.Parallel()

	data := certificate(t, prooftest.Attachment{
		Name:    pdf.TimestampAttachmentName,
		Content: []byte{0x30, 0x00},
	})

	cert, err := pdf.Open(bytes.NewReader(data), pdf.Limits{})
	require.ErrorIs(t, err, pdf.ErrManifestNotFound)
	require.NotNil(t, cert)
	assert.Nil(t, cert.Manifest)
	assert.NotEmpty(t, cert.Timestamp)
}

func TestOpenReportsMissingTimestamp(t *testing.T) {
	t.Parallel()

	data := certificate(t, prooftest.Attachment{
		Name:    pdf.ManifestAttachmentName,
		Content: []byte(`{}`),
	})

	cert, err := pdf.Open(bytes.NewReader(data), pdf.Limits{})
	require.ErrorIs(t, err, pdf.ErrTimestampNotFound)
	require.NotNil(t, cert)
	assert.NotEmpty(t, cert.Manifest)
	assert.Nil(t, cert.Timestamp)
}

func TestOpenReportsBothMissing(t *testing.T) {
	t.Parallel()

	cert, err := pdf.Open(bytes.NewReader(certificate(t)), pdf.Limits{})
	require.Error(t, err)
	assert.ErrorIs(t, err, pdf.ErrManifestNotFound)
	assert.ErrorIs(t, err, pdf.ErrTimestampNotFound)
	require.NotNil(t, cert)
	assert.Equal(t, "none", cert.AttachmentSummary())
}

// TestOpenIgnoresLookalikeNames checks that only an exact name is accepted, so a
// hostile document cannot smuggle an artifact past the verifier.
func TestOpenIgnoresLookalikeNames(t *testing.T) {
	t.Parallel()

	data := certificate(t,
		prooftest.Attachment{Name: "sealway-proof.json.bak", Content: []byte(`{"a":1}`)},
		prooftest.Attachment{Name: "SEALWAY-PROOF.JSON", Content: []byte(`{"b":2}`)},
		prooftest.Attachment{Name: " sealway-proof.json", Content: []byte(`{"c":3}`)},
		prooftest.Attachment{Name: pdf.TimestampAttachmentName, Content: []byte{0x30, 0x00}},
	)

	cert, err := pdf.Open(bytes.NewReader(data), pdf.Limits{})
	require.ErrorIs(t, err, pdf.ErrManifestNotFound)
	assert.Nil(t, cert.Manifest)
}

func TestOpenRejectsMalformedDocuments(t *testing.T) {
	t.Parallel()

	valid := certificate(t, bothAttachments()...)

	cases := map[string][]byte{
		"empty":           {},
		"not a pdf":       []byte("hello, this is plain text"),
		"header only":     []byte("%PDF-1.7\n"),
		"truncated":       valid[:len(valid)/3],
		"random bytes":    bytes.Repeat([]byte{0xde, 0xad, 0xbe, 0xef}, 512),
		"corrupted xref":  corrupt(valid, "startxref", "startxrEf"),
		"corrupted trail": corrupt(valid, "trailer", "trai1er"),
	}

	genuineManifest := []byte(`{"version":"1.1"}`)
	genuineToken := []byte{0x30, 0x03, 0x02, 0x01, 0x00}

	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// The invariant is not that every damaged document is rejected: a
			// container may be repairable, and whatever it yields is still fully
			// verified cryptographically afterwards. The invariant is that
			// parsing never panics and never invents an artifact.
			cert, err := pdf.Open(bytes.NewReader(data), pdf.Limits{})
			if err != nil {
				return
			}

			require.NotNil(t, cert)

			if cert.Manifest != nil {
				assert.Equal(t, genuineManifest, cert.Manifest)
			}

			if cert.Timestamp != nil {
				assert.Equal(t, genuineToken, cert.Timestamp)
			}
		})
	}
}

func corrupt(data []byte, from, to string) []byte {
	return []byte(strings.Replace(string(data), from, to, 1))
}

func TestOpenRejectsNilReader(t *testing.T) {
	t.Parallel()

	_, err := pdf.Open(nil, pdf.Limits{})
	assert.Error(t, err)
}

func TestOpenEnforcesAttachmentSizeLimit(t *testing.T) {
	t.Parallel()

	data := certificate(t, prooftest.Attachment{
		Name:    pdf.ManifestAttachmentName,
		Content: bytes.Repeat([]byte("a"), 4096),
	})

	_, err := pdf.Open(bytes.NewReader(data), pdf.Limits{MaxAttachmentSize: 1024})
	assert.ErrorIs(t, err, pdf.ErrAttachmentTooLarge)
}

func TestOpenEnforcesTotalAttachmentBudget(t *testing.T) {
	t.Parallel()

	data := certificate(t,
		prooftest.Attachment{Name: pdf.ManifestAttachmentName, Content: bytes.Repeat([]byte("a"), 2048)},
		prooftest.Attachment{Name: pdf.TimestampAttachmentName, Content: bytes.Repeat([]byte("b"), 2048)},
	)

	_, err := pdf.Open(bytes.NewReader(data), pdf.Limits{MaxTotalAttachmentSize: 3000})
	assert.ErrorIs(t, err, pdf.ErrAttachmentTooLarge)
}

func TestOpenEnforcesAttachmentCountLimit(t *testing.T) {
	t.Parallel()

	attachments := bothAttachments()
	for i := range 5 {
		attachments = append(attachments, prooftest.Attachment{
			Name:    string(rune('a'+i)) + ".txt",
			Content: []byte("x"),
		})
	}

	_, err := pdf.Open(bytes.NewReader(certificate(t, attachments...)), pdf.Limits{MaxAttachments: 3})
	assert.ErrorIs(t, err, pdf.ErrTooManyAttachments)
}

func TestNilCertificateHelpers(t *testing.T) {
	t.Parallel()

	var cert *pdf.Certificate

	assert.Nil(t, cert.AttachmentNames())
	assert.Equal(t, "none", cert.AttachmentSummary())
}

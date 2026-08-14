// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package prooftest

import (
	"bytes"
	"fmt"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"

	"github.com/sealway-hq/sealway-verifier/internal/pdfconfig"
)

// Names of the embedded artifacts a Sealway certificate carries.
const (
	ManifestAttachmentName  = "sealway-proof.json"
	TimestampAttachmentName = "proof-timestamp.tsr"
)

// Attachment is one embedded file of a generated certificate.
type Attachment struct {
	Name        string
	Description string
	Content     []byte
}

// BuildCertificate produces a certificate document embedding the given
// attachments.
//
// The result is a real document written by the same library the verifier reads
// with, so tests exercise the production extraction path rather than a stub.
func BuildCertificate(publicID string, attachments []Attachment) ([]byte, error) {
	conf := pdfconfig.NewConfiguration()
	conf.Cmd = model.ADDATTACHMENTS

	ctx, err := pdfcpu.CreateContextWithXRefTable(conf, types.PaperSize["A4"])
	if err != nil {
		return nil, fmt.Errorf("prooftest: cannot create the certificate: %w", err)
	}

	ctx.EnsureVersionForWriting()

	for _, a := range attachments {
		att := model.Attachment{
			Reader:   bytes.NewReader(a.Content),
			ID:       a.Name,
			FileName: a.Name,
			Desc:     a.Description,
		}

		if err := ctx.AddAttachment(att, false); err != nil {
			return nil, fmt.Errorf("prooftest: cannot attach %q: %w", a.Name, err)
		}
	}

	_ = publicID

	var buf bytes.Buffer
	if err := api.WriteContext(ctx, &buf); err != nil {
		return nil, fmt.Errorf("prooftest: cannot write the certificate: %w", err)
	}

	return buf.Bytes(), nil
}

# Third-party notices

Sealway Verifier links the following open-source modules. Their licences are
reproduced in their respective repositories and in the Go module cache of any
build. Several of them require that this notice accompany a redistributed
binary.

Licences were reviewed for compatibility with redistribution under the PolyForm
Shield License 1.0.0. Every one of them is permissive; none is copyleft.

## Linked into the released binary

| Module | Version | Licence | Why it is used |
| --- | --- | --- | --- |
| `github.com/pdfcpu/pdfcpu` | v0.15.0 | Apache-2.0 | Reading the certificate document and extracting its embedded attachments |
| `github.com/digitorus/pkcs7` | v0.0.0-20250730155240 | MIT | CMS SignedData parsing and signature verification for the RFC 3161 token |
| `github.com/hyperscale-stack/merkle` | v1.0.0 | MIT (see note below) | The Merkle tree construction of the public Sealway proof profile |
| `github.com/spf13/cobra` | v1.10.2 | Apache-2.0 | Command line interface |
| `github.com/spf13/pflag` | v1.0.10 | BSD-3-Clause | Flag parsing, required by cobra |
| `github.com/inconshreveable/mousetrap` | v1.1.0 | Apache-2.0 | Required by cobra on Windows |
| `golang.org/x/text` | v0.40.0 | BSD-3-Clause | Unicode normalization when matching source file names |
| `golang.org/x/crypto` | v0.54.0 | BSD-3-Clause | Required by pdfcpu |
| `golang.org/x/image` | v0.44.0 | BSD-3-Clause | Required by pdfcpu |
| `github.com/hhrutter/tiff` | v1.0.6 | BSD-3-Clause | Required by pdfcpu |
| `github.com/mattn/go-runewidth` | v0.0.27 | MIT | Required by pdfcpu |
| `github.com/clipperhouse/uax29/v2` | v2.7.0 | MIT | Required by pdfcpu |
| `go.yaml.in/yaml/v3` | v3.0.5 | MIT | Required by pdfcpu |
| `go.opentelemetry.io/otel` | v1.42.0 | Apache-2.0 | Required by hyperscale-stack/merkle |
| `go.opentelemetry.io/otel/metric` | v1.42.0 | Apache-2.0 | Required by OpenTelemetry |
| `go.opentelemetry.io/otel/trace` | v1.42.0 | Apache-2.0 | Required by OpenTelemetry |
| `go.opentelemetry.io/auto/sdk` | v1.2.1 | Apache-2.0 | Required by OpenTelemetry |
| `github.com/go-logr/logr` | v1.4.3 | Apache-2.0 | Required by OpenTelemetry |
| `github.com/go-logr/stdr` | v1.2.2 | Apache-2.0 | Required by OpenTelemetry |
| `github.com/cespare/xxhash/v2` | v2.3.0 | MIT | Required by OpenTelemetry |

## Test-only

These are not linked into the released binary.

| Module | Version | Licence | Why it is used |
| --- | --- | --- | --- |
| `github.com/stretchr/testify` | v1.11.1 | MIT | Assertions, and the mock runtime behind the generated test mocks |
| `github.com/stretchr/objx` | v0.5.2 | MIT | Required by testify/mock |
| `github.com/davecgh/go-spew` | v1.1.1 | ISC | Required by testify |
| `github.com/pmezard/go-difflib` | v1.0.0 | BSD-2-Clause | Required by testify |
| `gopkg.in/yaml.v3` | v3.0.1 | MIT | Required by testify |

The generated mocks under `internal/mocks/` are the only code that imports
`testify/mock`. They live under `internal/` precisely so that neither the mocks
nor testify become part of the public API, and `go list -deps ./apps/cli`
confirms testify is not linked into the released binary.

The generator itself, `github.com/vektra/mockery/v3` (BSD-3-Clause), is invoked
through `go run` and is not a module dependency.

## Note on `github.com/hyperscale-stack/merkle`

Every source file of that module carries the header

> Use of this source code is governed by a MIT license that can be found in the
> LICENSE file.

but the published `v1.0.0` module does not actually contain a `LICENSE` file. The
intent is unambiguous and the module is published by the same authors as this
repository, so this is a packaging omission rather than a licensing question. It
should be corrected upstream before this repository is made public, so that the
dependency carries its licence text the way redistribution expects.

## What this project deliberately avoids

- No cgo, so no native library licences enter the build.
- No external executable is invoked, so no OpenSSL, `pdftotext` or similar tool
  is a runtime dependency.
- No copyleft dependency, direct or indirect.
- No commercial or source-restricted dependency.
- No dependency requires an API key, an account or any credential.

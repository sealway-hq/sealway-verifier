# Sealway Verifier

Independent verification tooling for Sealway proofs.

Sealway Verifier recomputes, from scratch, every cryptographic claim a Sealway
proof makes. It does not ask a Sealway service whether a proof is good: it reads
the certificate, recomputes the digests, rebuilds the Merkle trees, verifies the
RFC 3161 timestamp signature and reads the anchored payload straight off the
public blockchains. Nothing in this repository needs a Sealway account, a Sealway
API or any credential.

It exists so that anyone holding a Sealway proof can check it without trusting
Sealway, and so that the verification logic itself can be audited line by line.

---

## What a proof is

```text
original file
  ↓  SHA-512 of the raw bytes
Merkle leaf
  ↓  Merkle tree over all certified items
proof Merkle root
  ↓  RFC 3161 qualified timestamp over that root
timestamped proof root
  ↓  Merkle inclusion proof
accumulator Merkle root
  ↓  transaction payload
public blockchain anchors
```

Every file uses the same primary proof hash, `SHA-512(raw file bytes)`. There is
no content-type-specific digest, no canonicalization and nothing derived from the
file name, the MIME type or any metadata.

## Source of truth

The **certificate is the only authoritative input**. It is a PDF/A-3b document
whose visible pages are for humans and whose embedded attachments are what the
machine verifier consumes:

- `sealway-proof.json` — the machine readable proof manifest
- `proof-timestamp.tsr` — the DER encoded RFC 3161 artifact

A proof bundle may also carry loose copies of these two files next to the
certificate. They exist so that humans and third-party tooling can reach the data
easily. **They are never used as a fallback authority.** Whether you hand the
verifier a bundle or a bare certificate, the manifest and the timestamp token are
always read out of the certificate, so there is exactly one verification path.

The verifier does compare the loose copies against the certificate and reports a
contradiction, because a bundle whose copies disagree with its certificate is
worth knowing about. That comparison never feeds the cryptographic result.

---

## Installation

Download a binary from the [releases page](https://github.com/sealway-hq/sealway-verifier/releases),
or build from source:

```bash
go build -o sealway-verifier ./apps/cli
```

Go 1.25 or newer. The build is pure Go with no cgo, so cross compiling needs
nothing beyond the toolchain.

---

## Usage

```bash
# A complete proof bundle: everything needed for a full verification
sealway-verifier verify proof.zip

# A certificate on its own: partial verification
sealway-verifier verify certificate.pdf

# A certificate together with the files it certifies
sealway-verifier verify certificate.pdf --source document.pdf
sealway-verifier verify certificate.pdf --source file1.pdf --source photo.jpg
sealway-verifier verify certificate.pdf --sources-dir ./files

# Without any network access
sealway-verifier verify proof.zip --offline

# Machine readable output
sealway-verifier verify proof.zip --json
```

The input kind is decided by inspecting the file's leading bytes, not its
extension, so a renamed bundle or certificate still verifies.

### Options

| Flag | Meaning |
| --- | --- |
| `--source`, `-s` | An original file certified by the proof. Repeatable. |
| `--sources-dir` | A directory holding the original files. |
| `--json` | Write the canonical verification report as JSON. |
| `--offline` | Disable every network call. Anchor checks become skipped. |
| `--verbose`, `-v` | Explain successful checks as well. |
| `--no-color` | Disable coloured output. `NO_COLOR` is honoured too. |
| `--timeout` | Maximum duration of a single blockchain lookup. |
| `--anchor-endpoint` | Override a network's public endpoint, as `network=url`. Repeatable. |
| `--trust-source` | Where to read the European Trusted Lists: `eu` (default), a mirror base URL, or `none`. |
| `--trust-dir` | A trust snapshot on disk, read instead of the network. |
| `--timestamp-roots` | PEM bundle of trust anchors for the timestamp signer chain. |

### How supplied files are matched

Matching is deterministic and never fuzzy:

1. a file whose base name is exactly the certified file name is paired with that
   item. Names are compared after Unicode NFC normalization, so a name stored
   decomposed on macOS and composed elsewhere is recognised as the same name. A
   certified name shared by several items is skipped rather than guessed;
2. a file that no certified name claimed is then paired by its SHA-512, which is
   the only truly authoritative link between a file and a certified item.

Pairing asserts nothing about the file: its digest is still recomputed and
compared with the certified leaf.

A file you name explicitly with `--source`, or that a bundle carries in its
`files/` directory, is asserted to belong to the proof, so one that matches no
certified item is reported as a failure. A file merely discovered by
`--sources-dir` is disregarded instead, because a directory may legitimately hold
unrelated files.

---

## Complete, partial and invalid

Every step reports exactly one of `valid`, `invalid` or `skipped`. A step whose
prerequisites were unavailable is always **skipped with an explicit reason**, and
is never reported as successful.

| Result | Exit code | Meaning |
| --- | --- | --- |
| `COMPLETE_VALID` | `0` | Every applicable step was performed and none failed. |
| `INVALID` | `1` | At least one cryptographic or structural step failed. |
| *(operational error)* | `2` | The tool could not run the verification at all. |
| `PARTIAL_VALID` | `3` | No step failed, but at least one could not be performed or could not conclude. |

A step reports one of four outcomes. Two of them mean the question was not
answered, and they are deliberately distinct:

- `skipped` — the step was **not attempted**, because a prerequisite or a
  capability was missing (no source files, `--offline`);
- `indeterminate` — the step **was attempted and could not conclude**, because
  the evidence it needs is absent, expired or impossible to authenticate (no
  Trusted List source, a list whose signature does not verify).

Neither ever reads as success, and neither is turned into a failure: an absence
of proof is not a proof of absence.

A cryptographically invalid proof is a verification outcome, not a tool failure:
it exits `1`, while an unreadable input exits `2`.

A partial result is **not** the same as a valid one. When you verify a
certificate without its original files, the report says plainly that the
certified data is internally consistent, timestamped and anchored, but that no
claim is made about files it never saw.

### Verification stages

```text
Certificate            document parsed, embedded manifest and RFC 3161 token
                       extracted, manifest structure validated
Source files           SHA-512 recomputed from the raw bytes of every file
Proof Merkle tree      leaves, rebuilt root, certified root consistency,
                       individual inclusion proofs
Qualified timestamp    token structure, CMS signature, signer usage, message
                       imprint against the proof root, declared metadata,
                       signer certificate path, qualified eIDAS status
Accumulator            inclusion proof, recomputed accumulator root
Blockchain anchors     the anchored payload of each declared transaction
```

### What legitimately becomes `SKIPPED`

| Step | Outcome | Why |
| --- | --- | --- |
| Source file checks | `skipped` | The original files were not provided. |
| Rebuilt Merkle root | `skipped` | The tree cannot be rebuilt from files that were not provided. |
| Blockchain anchors | `skipped` | `--offline`, an unreachable endpoint, or a network with no provider. |
| Signer certificate path | `indeterminate` | Neither a Trusted List source nor `--timestamp-roots` was available. |
| Qualified electronic timestamp | `indeterminate` | No Trusted List source, or the lists could not be authenticated. |
| Certificate digital signature | `skipped` | Document signature verification is not implemented in this version. |
| Signer certificate revocation | `skipped` | Revocation checking is not implemented in this version. |

The last two are documented scope limits that do not downgrade the result. Every
other outcome above keeps the run from being complete, because something that was
not established must not read as if it had been.

### Revocation is declared, not checked

The verifier reads no certificate revocation list and queries no OCSP responder,
so it cannot say whether the certificate that signed the timestamp had been
revoked at the time the token asserts.

It reports that rather than passing over it, because "a valid certification path"
means, in RFC 5280 and in ETSI TS 119 615, a path whose certificates were also
found unrevoked, and a reader is entitled to assume the words carry their usual
meaning. The step therefore appears in every report as `skipped`, together with
the revocation list and OCSP addresses the certificate itself publishes, so that
whoever wants the answer is told where to obtain it.

What this leaves unproven is specific and worth stating plainly: had the signing
key been compromised and its certificate revoked before that time, this verifier
would not have noticed. Everything else the timestamp establishes still holds.

---

## The public cryptographic profile

```text
File hash            SHA-512(raw file bytes)
Merkle leaf          the file hash, unmodified
Leaf ordering        ascending certified item position
Odd-node behaviour   duplicate the last node of the level
Internal node        SHA-512(0x01 || left || right)
left / right         the raw 64-byte digests, never their hexadecimal text
```

Two consequences are worth stating explicitly, because both are easy to get
wrong:

- a **single-leaf tree is not the leaf**. The odd-node rule applies to every
  incomplete level including the leaf level, so a one-item proof has a root of
  `SHA-512(0x01 || leaf || leaf)`;
- internal nodes hash the **raw bytes** of the child digests. Hashing their ASCII
  hexadecimal representation produces a different, wrong root.

The proof Merkle root is what the RFC 3161 token timestamps: the token's message
imprint must equal that root byte for byte. The same root is a leaf of a second
Merkle tree, the accumulator, and the manifest's inclusion proof lets anyone
recompute the accumulator root from the proof root. That accumulator root is what
is published on the public blockchains.

## Blockchain anchors

| Network | How the payload is read | Default public endpoint |
| --- | --- | --- |
| Algorand | transaction `note` field, via a public indexer | `https://mainnet-idx.algonode.cloud` |
| Polygon | transaction `input` data, via `eth_getTransactionByHash` | `https://polygon-bor-rpc.publicnode.com` |
| Base | transaction `input` data, via `eth_getTransactionByHash` | `https://base-rpc.publicnode.com` |

A transaction existing proves nothing. What is verified is the payload actually
carried on chain: it must be, or contain, the certified accumulator Merkle root.

Every endpoint is an ordinary unauthenticated public node, needs no API key and
can be replaced with `--anchor-endpoint`. Standard JSON-RPC is used rather than a
block explorer API, so the same verification can run from a browser.

An endpoint that cannot be reached **skips** the check. It never fails it: an
unreachable network must not look like a broken proof.

---

## Qualified eIDAS status

Whether a timestamp is a *qualified electronic time stamp* is a legal property,
not a cryptographic one. A valid signature says who produced a token; only the
European Trusted Lists say whether that producer was recognised as qualified, and
only for the instant the token asserts.

A token may carry an ETSI EN 319 422 statement claiming qualified status. That is
a claim written by its issuer, and it is never treated as an answer.

### How it is established

```text
the anchor published in the Official Journal
  ↓ verifies
the European List of Trusted Lists          ec.europa.eu/tools/lotl/eu-lotl.xml
  ↓ pins the signing certificates of
the national Trusted List                   e.g. tsl.digital.gob.es/TSL.xml
  ↓ publishes
a qualified timestamp service (TSA/QTST) and its status history
  ↓ a certification path is built from
the certificate that signed the token
```

Nothing is read before it has been authenticated, and the whole determination is
made **at the time the token asserts**, never at the moment of verification. A
service recognised then does not stop having been recognised because its
recognition ended later, and a certificate that has since expired was still valid
when it signed. That is what the service status history is for.

### Matching is on the certification path

A Trusted List normally identifies a service by the **authority that issues** its
certificates, not by each signing certificate. Looking only for the signing
certificate therefore answers the wrong question, and can answer it wrongly when
a provider restructures its entries.

When several entries cover the same certificate and disagree, all of them are
reported in the check details rather than one being chosen in silence.

### Bootstrap anchor

Validating the lists does not remove the need for a trust anchor, it moves it.
The one certificate this verifier asks you to take on faith is the European
Commission's list-of-lists signer, shipped as readable PEM at
`packages/verifier/trust/bootstrap/eu-lotl-signer.pem` with its SHA-256 recorded
in the source and checked by a test.

Compare it with the publication in the Official Journal of the European Union
before relying on it. The set is append-only: a new certificate is added when the
Commission rotates, and an old one is never removed, because a list issued under
it must stay verifiable.

### Working offline, and from a browser

The official endpoints send no cross-origin headers, so a browser cannot read
them directly. Take a snapshot instead:

```bash
sealway-verifier trust fetch ./trust --territory ES
sealway-verifier verify proof.zip --trust-dir ./trust --offline
```

A snapshot holds the **official signed documents unchanged**, so whoever reads it
verifies the European signatures themselves. A mirror is therefore a transport
and never an authority: it can withhold or delay material, but it cannot invent a
qualified service. Serve a snapshot over HTTPS and point a browser build at it
with `--trust-source https://…`.

---

## In a browser

The same verification code compiles to WebAssembly, so a page can verify a proof
without uploading it anywhere and without contacting any Sealway service.

```bash
make wasm-serve   # builds dist/web and serves it on http://localhost:8080
```

The page picks a `.zip` bundle, hands the bytes to the module and renders the
canonical report — the same report `--json` writes. Building it separately:

```bash
make wasm         # dist/web: the module, the page and a Trusted List snapshot
```

### As a package

The browser module is published to GitHub Packages as
`@sealway-hq/verifier-web`, on every release. It carries the module, the Go
runtime shim that is version-locked to it, and a wrapper that turns the global
below into an ESM import. See
[`apps/wasm/npm/README.md`](apps/wasm/npm/README.md).

```js
import { createVerifier } from '@sealway-hq/verifier-web';

const verifier = await createVerifier({ trustBaseUrl: '/trust' });
const report = await verifier.verify(file);
```

The package is private: publication is governed by the licence, not by the
registry being open.

### The API a page calls

```js
const report = JSON.parse(await sealwayVerifier.verify(bytes, {
  verifyAnchors: false,   // read the public blockchains, when they allow it
  timeoutSeconds: 20,
  trust: { lotl, lists: { ES } },   // the official signed documents, unchanged
}));

sealwayVerifier.schemaVersion;      // the report contract this build produces
```

`verify` takes a `Uint8Array` or an `ArrayBuffer` and returns a promise. It
resolves with the report as JSON, and rejects only on an operational failure such
as an unreadable archive — a proof that does not hold resolves normally, with a
result of `invalid`.

The trust material is handed in by the page rather than fetched by the module,
because the official European endpoints send no cross-origin headers. Supplying
it is not a way to be believed: the module verifies the European signatures
against its own pinned anchor, so material that is not genuinely signed by the
Commission cannot produce a qualified verdict — it produces `indeterminate`. A
page that supplies nothing gets `indeterminate` too, never a claim of
qualification.

Anchors are only read when the page asks. Public endpoints may or may not allow a
cross-origin request; when they do not, the anchor checks are reported as skipped
rather than failed.

---

## What a successful check proves

| Check | Proves |
| --- | --- |
| Source SHA-512 | The supplied file is byte-for-byte identical to the certified file hash. |
| Proof Merkle root | The verified file hashes reconstruct the certified proof root. |
| RFC 3161 timestamp | Subject to trusting the timestamping authority, the proof root existed at the asserted time. |
| Signer certificate path | The signing certificate chains to an authority a Trusted List publishes, validated at the asserted time. Revocation was not examined. |
| Qualified electronic timestamp | The service was recorded as qualified in an authenticated national Trusted List at the asserted time. |
| Accumulator inclusion | The proof root is included in the certified accumulator root. |
| Blockchain anchor | The expected accumulator root is present in the referenced public transaction. |

Three notions are kept strictly apart, because conflating them would overclaim:
the CMS signature being cryptographically valid, the signer certificate chaining
to a recognised authority, and the timestamp being a *qualified* electronic time
stamp under eIDAS. Each is a separate check with its own outcome.

**The verifier verifies cryptographic evidence, not legal ownership.** It makes
no claim about authorship, ownership, copyright, legal title, or the truthfulness
of the contents of a file.

---

## Using it as a library

```go
import "github.com/sealway-hq/sealway-verifier/packages/verifier"

v := verifier.New()

report, err := v.VerifyBundle(ctx, readerAt, size)
if err != nil {
    // operational failure: the proof could not be read at all
}

switch report.Result {
case verifier.ResultCompleteValid:
case verifier.ResultPartialValid:
case verifier.ResultInvalid:
}
```

The report is the single contract shared by every front end. It is deterministic,
JSON serializable and free of presentation concerns, so the command line
interface, a desktop application and a browser build can all consume the same
structure.

The Merkle primitives are exposed as pure functions for standalone tools:

```go
root, err := verifier.ComputeMerkleRoot(leaves)
siblings, root, err := verifier.GenerateMerkleProof(leaves, index)
ok, err := verifier.VerifyMerkleProof(leaf, siblings, root)
digest, err := verifier.HashSource(reader)
```

The library is pure Go with no cgo, no shell out and no mandatory filesystem
access in its cryptographic paths. It reads through `io.Reader` and
`io.ReaderAt`, takes its HTTP client by injection and keeps no global mutable
state. `packages/...` compiles for `js/wasm` and `wasip1/wasm`, and that is
checked on every build.

---

## Handling of untrusted input

Proof bundles, certificates, manifests and source files are all treated as
hostile.

- **Archives** are never extracted to disk. Absolute paths, `..` traversal,
  backslash separators, drive letters, NUL bytes, symbolic links and every other
  irregular file mode are rejected, as are duplicate entries. Entry counts and
  sizes are bounded, and metadata entries share a total budget so a decompression
  bomb cannot expand past it.
- **Certificates** yield only the two expected attachments, matched by exact
  name. Attachments are read, never executed, and no embedded action or script is
  interpreted.
- **Manifests** are size bounded, reject malformed digests, duplicate or non
  contiguous item positions, inconsistent leaf indices, invalid sibling
  directions and contradictory roots. Malformed values are reported, never
  repaired.
- **Responses** from public endpoints are size bounded, and transaction
  identifiers are validated before they ever reach a request.

Fuzz targets cover manifest parsing, digest decoding, Merkle proof verification,
timestamp parsing, archive reading and the two whole verification entry points.
The requirement they encode is simple: untrusted input must never panic.

---

## Development

```bash
make test        # go test ./...
make race        # go test -race ./...
make lint        # golangci-lint run ./...
make cover       # coverage profile and total
make fuzz        # short fuzzing run over every target
make cross       # every release target plus js/wasm
make build       # bin/sealway-verifier
make wasm        # dist/web, the browser demonstration
make wasm-test   # the browser module, in the js/wasm runtime (needs node)
```

The end-to-end suite verifies a real production proof bundle in `testdata/`, with
the blockchain anchors served from recorded responses so that no ordinary test
run depends on a third party being up. To check the anchors against the live
public networks:

```bash
make test-live   # or: SEALWAY_VERIFIER_LIVE_TESTS=1 go test ./tests/e2e/
```

### Layout

```text
apps/cli/                  command line interface
apps/wasm/                 browser module and its demonstration page
  npm/                     the package published to GitHub Packages
packages/verifier/         public API and verification pipeline
  proof/                   manifest model and validation
  merkle/                  Merkle operations of the public profile
  pdf/                     certificate attachment extraction
  timestamp/               RFC 3161 parsing and signature verification
  trustlist/               European Trusted Lists, ETSI TS 119 612
    xmldsig/               XML signature verification of those lists
  trust/                   trust material and how it is obtained
    bootstrap/             the anchor published in the Official Journal
  eidas/                   qualified status determination
  anchor/                  blockchain provider interface and implementations
  bundle/                  safe archive reading
  report/                  canonical verification report
  source/                  filesystem helpers, not used by the core
tests/functional/          realistic proof structures, including tampered ones
tests/e2e/                 the production fixture in testdata/
```

---

## Licence

Source available under the [PolyForm Shield License 1.0.0](LICENSE).

The source is public so that anyone can audit exactly how a Sealway proof is
verified, and so that Sealway customers can verify their own proofs with tooling
they can read. It is not free software: the licence permits any use except
building a product that competes with Sealway.

Copyright 2026 Ondarea Holding SAS.

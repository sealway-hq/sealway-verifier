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
| `PARTIAL_VALID` | `3` | No step failed, but at least one could not be performed. |

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
                       imprint against the proof root, declared metadata
Accumulator            inclusion proof, recomputed accumulator root
Blockchain anchors     the anchored payload of each declared transaction
```

### What legitimately becomes `SKIPPED`

| Step | Why |
| --- | --- |
| Source file checks | The original files were not provided. |
| Rebuilt Merkle root | The tree cannot be rebuilt from files that were not provided. |
| Blockchain anchors | `--offline`, an unreachable endpoint, or a network with no provider. |
| Signer certificate chain | No trust anchors were supplied; see `--timestamp-roots`. |
| Qualified trust-list validation | EU trusted-list validation is not implemented in this version. |
| Certificate digital signature | Document signature verification is not implemented in this version. |

The last three are documented scope limits rather than missing evidence, so they
do not by themselves downgrade a result to partial. Every other skip does.

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

## What a successful check proves

| Check | Proves |
| --- | --- |
| Source SHA-512 | The supplied file is byte-for-byte identical to the certified file hash. |
| Proof Merkle root | The verified file hashes reconstruct the certified proof root. |
| RFC 3161 timestamp | Subject to trusting the timestamping authority, the proof root existed at the asserted time. |
| Accumulator inclusion | The proof root is included in the certified accumulator root. |
| Blockchain anchor | The expected accumulator root is present in the referenced public transaction. |

Three notions are kept strictly apart, because conflating them would overclaim:
the CMS signature being cryptographically valid, the signer certificate chaining
to a trusted root, and the timestamp being a *qualified* electronic time stamp
under eIDAS. This version establishes the first, supports the second when you
supply trust anchors, and never asserts the third.

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
packages/verifier/         public API and verification pipeline
  proof/                   manifest model and validation
  merkle/                  Merkle operations of the public profile
  pdf/                     certificate attachment extraction
  timestamp/               RFC 3161 parsing and signature verification
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

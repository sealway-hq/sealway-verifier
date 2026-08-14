# Repository guidelines

Sealway Verifier independently verifies Sealway proofs. It is the tooling a
customer uses to check a proof **without trusting Sealway**, and the code a third
party reads to audit how that verification works.

Both of those purposes constrain everything below. Read this file before making
changes.

---

## 1. Confidentiality — this repository is public

The Sealway platform is closed source. This repository is not. Never introduce:

- Sealway infrastructure: internal hostnames, private endpoints, database
  models, queue names, deployment details.
- Credentials of any kind, including test ones.
- References to the closed-source monorepo (`github.com/sealway-hq/platform`)
  or to its package layout.
- Proprietary algorithms. Proof verification uses `SHA-512(raw file bytes)` and
  nothing else. Do not reconstruct legacy or content-type-specific hashing.

Only what is strictly necessary to independently verify a proof belongs here.

Before any commit that touches configuration or documentation, check that no
endpoint other than the public blockchain ones appears:

```bash
grep -rhoE 'https?://[a-zA-Z0-9._/-]+' --include='*.go' apps packages internal | sort -u
```

---

## 2. Non-negotiable design rules

These are correctness properties, not preferences. A change that breaks one is
wrong even if the tests pass.

1. **The certificate is the only authoritative input.** The proof manifest and
   the RFC 3161 token are always read from the certificate's embedded
   attachments. The loose copies a bundle carries are *never* a fallback. There
   is exactly one verification path for ZIP and PDF input.
2. **Never report a missing prerequisite as `VALID`.** A step that could not be
   performed is `SKIPPED` with a message that says why. There are exactly three
   statuses: `valid`, `invalid`, `skipped`.
3. **Never overclaim.** A valid CMS signature is not a trusted chain, and a
   trusted chain is not eIDAS qualification. Keep the three apart in code and in
   report wording.
4. **Rebuild from evidence, not from claims.** When source files are available,
   the Merkle tree is rebuilt from their recomputed digests, never from the
   manifest's leaf hashes. Declared roots are recomputed before being compared.
5. **A transaction existing proves nothing.** An anchor is verified by reading
   the payload actually carried on chain and comparing it with the accumulator
   root.
6. **Errors and verification failures are different.** An unreadable input is an
   operational error (exit 2). A proof that does not hold is a verification
   outcome (exit 1). Never conflate them.
7. **An unreachable network skips, never fails.** A third party being down must
   not look like a broken proof.
8. **Untrusted input must never panic.** Archives, certificates, manifests,
   source files and endpoint responses are all hostile.

---

## 3. Portability

The core library must stay usable from a browser WebAssembly build. In
`packages/`:

- pure Go, no cgo, no shell out, no external binary;
- no mandatory filesystem access in cryptographic paths — use `io.Reader`,
  `io.ReaderAt`, byte slices;
- inject the HTTP client, never construct a global one;
- no global mutable state, no `init` side effects, no `os.Exit`, no `log.Fatal`;
- deterministic output.

Filesystem and terminal concerns belong in `apps/cli` or in
`packages/verifier/source`. `make cross` checks every release target plus
`js/wasm`, and CI does the same.

If a dependency forces global state on us, funnel it through a single guarded
setter — see `internal/pdfconfig`.

---

## 4. Test-driven development

Write the test first. It is not ceremony here: this is a verifier, and the tests
are what establish that it rejects what it should reject.

**The workflow for any behaviour change:**

1. Write a failing test that states the property in its name.
2. Make it pass.
3. Run `make test lint`.

**For every verification rule, test both directions.** A test that only proves a
good proof verifies is half a test. The valuable ones are the negatives: wrong
digest, forged path, wrong direction, mismatching imprint, tampered manifest,
anchor carrying the wrong payload.

**Testing rules:**

- Test through the public API. Reach into internals only when there is no other
  way to reach a branch.
- Cryptographic vectors come from an **independent** implementation, never from
  the code they verify. See the vectors in `packages/verifier/merkle`.
- Fixtures are generated at test time by `internal/prooftest`, which builds a
  real throwaway TSA, a real signed RFC 3161 token and a real certificate. Add
  tampered variants there rather than hand-rolling broken bytes.
- **Never mutate the production fixture** in `testdata/`. Read it, copy it,
  leave it byte-identical.
- No test may depend on a live third party. Use `httptest` or the generated
  mocks. Live checks go behind `SEALWAY_VERIFIER_LIVE_TESTS=1`.
- Use `t.Parallel()` unless the test needs `t.Setenv`.
- Add a fuzz seed when you fix a parser bug.

**Coverage** is currently ~92%. Treat a drop as a regression, but never add a
test purely to move the number: cover behaviour, not statements.

---

## 5. Mocks

Generated with mockery v3 into `internal/mocks/`, deliberately **not** in place:
this keeps `testify` and the mock types out of the public API.

```bash
make mocks         # regenerate
make mocks-check   # fail if the committed mocks are stale
```

Generated files are committed so the suite builds without the generator, and CI
verifies they are up to date.

Use a mock when the assertion is about **how a collaborator was called** —
arguments, call count, whether it was called at all. When the assertion is about
behaviour, prefer `httptest` or a small hand-written fake: they exercise the real
parsing and transport code, which a mock skips.

---

## 6. Commands

```bash
make test          # go test ./...
make race          # go test -race ./...
make cover         # coverage profile and total
make lint          # golangci-lint run ./...
make fmt           # golangci-lint fmt ./...
make fuzz          # short run over every fuzz target
make cross         # every release target plus js/wasm
make mocks         # regenerate test mocks
make test-live     # anchor checks against the live public networks
make build         # bin/sealway-verifier
```

`make lint` must be clean. Do not silence a linter with `//nolint` unless the
finding is genuinely wrong; when you do, give the specific linter and a reason.

---

## 7. Code style

- **Everything in English**: code, comments, commit messages, documentation.
- Every exported symbol has a GoDoc comment that says what it guarantees, not
  what it does mechanically.
- Comments explain **why**, especially where a rule is surprising. Two examples
  worth preserving: a single-leaf Merkle tree still duplicates its leaf, and
  internal nodes hash raw digest bytes rather than their hexadecimal text.
- Explicit errors, wrapped with `%w`. Sentinel errors for conditions a caller
  must distinguish.
- Small interfaces, dependency injection only where it buys testability or
  portability.
- Keep the public API small and intentional. Do not export something because a
  test needs it — restructure instead.
- Report messages are user-facing prose: full sentences, no jargon, and they
  must state precisely what was and was not proven.

---

## 8. Commit convention

Angular convention. Present tense, imperative, lower-case subject, no trailing
full stop.

```
<type>(<scope>): <subject>

<body: why, not what>

<footer: BREAKING CHANGE / Refs>
```

**Types**: `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `build`, `ci`,
`chore`, `style`, `revert`.

**Scopes**: `verifier`, `report`, `proof`, `merkle`, `pdf`, `timestamp`,
`anchor`, `bundle`, `source`, `cli`, `render`, `prooftest`, `repo`, `deps`.

```bash
feat(anchor): verify Base anchors through public JSON-RPC
fix(merkle): reject inclusion paths with an unknown sibling direction
test(timestamp): cover a response whose status is a rejection
docs(readme): document the partial verification result
```

A commit that changes verification behaviour must include the tests that cover
it. Keep each commit buildable and green.

---

## 9. Branches and pull requests

Branches: `feature/<slug>`, `fix/<slug>`, `chore/<slug>`.

Never commit directly to `main`.

A pull request should state what changed, why, and — when it touches
verification — what a reviewer should convince themselves of. CI must be green:
build, vet, test, race, lint, tidy, mock freshness, fuzz smoke and cross-build.

---

## 10. Dependencies

Prefer the standard library. Before adding a dependency:

- check the licence is permissive (no GPL/AGPL/LGPL, no commercial);
- check it is pure Go and cgo-free;
- record it in `THIRD_PARTY_NOTICES.md` with its licence and why it is used;
- confirm it does not leak into the released binary if it is test-only:

```bash
go list -deps ./apps/cli | grep <module>
```

No dependency may require an API key, an account or any credential.

---

## 11. Layout

```text
apps/cli/                  command line interface (thin adapter)
packages/verifier/         public API and verification pipeline
  proof/                   manifest model and validation
  merkle/                  Merkle operations of the public profile
  pdf/                     certificate attachment extraction
  timestamp/               RFC 3161 parsing and signature verification
  anchor/                  provider interface and public network implementations
  bundle/                  safe archive reading
  report/                  canonical verification report
  source/                  filesystem helpers, not imported by the core
internal/prooftest/        synthetic proof generator for tests
internal/mocks/            generated mocks
internal/pdfconfig/        guarded setup of the PDF library's global state
tests/functional/          realistic proof structures, including tampered ones
tests/e2e/                 the production fixture in testdata/
```

---

## 12. Out of scope for now

Do not implement here: the desktop application, the website integration, the
WASM JavaScript wrapper, proof creation, timestamp creation, blockchain
anchoring, or any Sealway backend integration.

The library must nevertheless keep exposing the primitives those will need:
`ComputeMerkleRoot`, `GenerateMerkleProof`, `VerifyMerkleProof`, `HashSource`.

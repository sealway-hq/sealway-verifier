# @sealway-hq/verifier-web

Verify a Sealway proof inside a page. The proof is read by WebAssembly in the
browser: nothing is uploaded, and no Sealway service is contacted.

This is the same verification code the command line tool runs, compiled to
`js/wasm`. It produces the same canonical report.

**Source available, not open source.** Use is governed by the
[PolyForm Shield License 1.0.0](https://github.com/sealway-hq/sealway-verifier/blob/main/LICENSE).
Read it before depending on this package.

## Install

The package is published to GitHub Packages, not to the public npm registry.
Point the scope at the right registry:

```ini
# .npmrc
@sealway-hq:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```

```bash
npm install @sealway-hq/verifier-web
```

The token needs the `read:packages` scope.

## Use

```js
import { createVerifier } from '@sealway-hq/verifier-web';

const verifier = await createVerifier({ trustBaseUrl: '/trust' });

const report = await verifier.verify(file, { verifyAnchors: true });

report.result;          // 'complete_valid' | 'partial_valid' | 'invalid'
report.sections;        // every check, with its status and why
```

`verify` takes a `File`, `Blob`, `ArrayBuffer` or `Uint8Array`, and reads either
container: a `.zip` proof bundle or a `.pdf` certificate on its own. The format
is detected from the bytes, so a page can accept whichever file someone was
given.

A certificate without its original files verifies everything the certificate
carries — the manifest, the timestamp, the accumulator, the anchors — and reports
the file dependent steps as skipped. Add the files to close that gap:

```js
await verifier.verify(certificate, { sources: [...fileInput.files] });
```

A source may be a `File`, as a picker or a drop hands it over, or
`{name, content}` when you already hold the bytes. The name matters: a certified
item is matched by the name of the file that produced it, so a source without one
is refused rather than silently reported as a file the proof does not cover.

**A certificate with its files gives 24 checks where the bundle gives 25**, and
the difference is not a gap. The extra one is `certificate.loose_copies`, which
compares the convenience copies of the manifest and the token that a bundle
carries beside the certificate. A certificate on its own has none, so there is
nothing to compare. Everything the files make possible — the source digests, the
rebuilt Merkle tree — is verified identically either way.

**Pass `verifyAnchors: true` for a complete verification.** It defaults to
`false` so that importing this package never makes an outbound request nobody
asked for — but the blockchain anchors are part of the proof, and leaving them
unread reports a sound proof as partial. The three public endpoints allow
cross-origin requests, so a browser does reach `complete_valid`; reading them is
the only step that leaves the browser.

A proof that does not hold **resolves normally**, with a result of `invalid`.
The promise rejects only on an operational failure — an archive that cannot be
read is a tool failure, not a verdict on the proof. Keep the two apart in your
interface.

### Four outcomes, and two of them are not answers

`valid` and `invalid` are conclusions. `skipped` means the step was not
attempted; `indeterminate` means it was attempted and the evidence did not
settle it. Neither ever reads as success, and an interface that renders them as
a green tick is misreporting.

## The other tools

Each returns the same `Report`, so one renderer serves all of them.

### A bare timestamp

```js
const report = await verifier.verifyTimestamp(token, { imprint });
```

`token` may be a `File`, bytes, or the base64 or hexadecimal text people paste.

The report carries **only the timestamp section**. A token is a statement about a
digest and a moment; nothing about a proof, its files or its anchors is present
to report on, and emitting skipped checks for them would report the absence of
things that were never part of the question.

Every check is performed by the code that runs inside a full verification, so a
token that verifies here verifies identically inside the proof that carries it.

`imprint` is optional. Without it the imprint is read and reported but compared
with nothing: a token says what it covers, and whether that is the *right* thing
is a question only you can ask.

Two checks behave differently here, and neither is a failure. `timestamp.metadata`
compares the token with a proof manifest, which a bare token has none of, so it
is out of scope. `timestamp.revocation` needs evidence a certificate normally
carries; supply it as `revocation` if you have it, or it stays unestablished.

### Reading a token without judging it

```js
const details = await verifier.inspectTimestamp(token);
details.signer.common_name;          // who issued it
details.signer.issuer_common_name;
details.signer.signature_algorithm;
details.qualified_statement;         // a claim by its issuer, never evidence
```

No verdict. Reading a token and believing it are different acts.

This does not decode the raw ASN.1 into a browsable tree. A general DER explorer
is a different tool, and shipping one inside a 3 MB WebAssembly module to fill a
UI panel is a poor trade — keep a JavaScript ASN.1 library for that panel.

### The Merkle profile

```js
// Rebuild a root from digests, and compare it if you know what to expect.
await verifier.verifyMerkle({ leaves, root });

// Or check that one leaf belongs to a tree.
await verifier.verifyMerkle({ leaf, path, root });
```

Digests may be `Uint8Array` or lower-case hexadecimal. Each `path` entry needs
its `position`, `"left"` or `"right"`: the profile folds
`SHA-512(0x01 || left || right)`, so the side changes the value.

Without a `root`, the tree is rebuilt and its root reported, but nothing is
concluded — computing is not concluding, and the check says so.

Two rules of this profile are where an independent implementation reliably
diverges, and both are applied here by the same code the full verification uses:
an incomplete level duplicates its last node, **including a tree of one leaf**,
and an internal node hashes the raw digest bytes of its children rather than
their hexadecimal text.

## Trust material

Qualified eIDAS status comes only from an authenticated European Trusted List.
Without one, `timestamp.qualified` is reported as `indeterminate` — the verifier
will not answer a question it has no evidence for, and will not accept the
timestamp issuer's own claim as an answer.

The official European endpoints send no cross-origin headers, so a browser
cannot read them. Serve the documents from your own origin instead:

```bash
sealway-verifier trust fetch ./public/trust --territory ES
```

That writes `lotl.xml` and `lists/es.xml` — the **official signed documents
unchanged**. This module verifies the European signatures itself against the
anchor it ships, so your server carries the bytes without becoming something
anyone has to trust. A stale or hostile mirror can withhold or delay material;
it cannot invent a qualified service.

**Refresh it on a schedule, not on deploy.** Member states republish their lists,
and a snapshot frozen into a build goes stale. Staleness is an availability
problem here, not a security one — but a list that no longer covers the moment
you are asking about leaves qualification undecided.

### Serving more than one territory

Which national list a proof needs is decided by the country in the certificate
that stamped it, not by configuration. Serve them all and the package fetches the
one it needs:

```bash
sealway-verifier trust fetch ./public/trust --all-territories
```

The territories come from the signed list of lists, so a member state added next
year is picked up without a change here. A list that cannot be fetched is named
and left out rather than failing the sweep.

This matters for weight. Every list the Union publishes comes to roughly 25 MB,
which is more than the WebAssembly module itself; a proof needs exactly one of
them, and only that one is downloaded. Changing eIDAS provider — from a Spanish
authority to a French one, say — then needs no change to your code.

`requiredTerritory(token)` answers the same question directly, for a host
deciding what to serve.

## Astro

Use a client-only island. Nothing here can run at build time, and you do not
want the module on pages that never verify anything.

```astro
---
// src/pages/verify.astro
import VerifyProof from '../components/VerifyProof.svelte';
---
<VerifyProof client:visible />
```

```js
// inside the component, on user action
const { createVerifier } = await import('@sealway-hq/verifier-web');
const verifier = await createVerifier({ trustBaseUrl: '/trust' });
const report = await verifier.verify(event.target.files[0]);
```

The dynamic `import()` keeps the module out of the initial bundle, so the
download starts when someone actually picks a file.

`trust/` goes in `public/`, which Astro copies verbatim.

### If your host does not serve `application/wasm`

Streaming instantiation requires that content type. This package falls back to
buffering the module when it is missing, so it works either way — but the
fallback holds the module in memory twice. Configuring the header is worth it.

### Serving the module yourself

By default the module is resolved from the package, and your bundler emits it as
a hashed asset. To serve it from `public/` instead — to control caching, or to
put it on a CDN — pass its URL:

```js
await createVerifier({ wasmUrl: '/sealway.wasm', trustBaseUrl: '/trust' });
```

## Weight

| | gzip | brotli |
| --- | --- | --- |
| `sealway.wasm` | 4.6 MB | 3.3 MB |
| Trusted Lists (LOTL + ES) | 768 kB | 628 kB |

Serve both compressed. The module is fetched once and caches well; give it a
long `max-age` and let the hashed filename handle invalidation.

## What a report proves

Cryptographic facts only. Nothing about authorship, ownership, copyright, legal
title, or the truthfulness of the contents of a file.

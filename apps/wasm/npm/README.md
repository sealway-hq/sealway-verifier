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

const report = await verifier.verify(file);   // a File, Blob, ArrayBuffer or Uint8Array

report.result;          // 'complete_valid' | 'partial_valid' | 'invalid'
report.sections;        // every check, with its status and why
```

A proof that does not hold **resolves normally**, with a result of `invalid`.
The promise rejects only on an operational failure — an archive that cannot be
read is a tool failure, not a verdict on the proof. Keep the two apart in your
interface.

### Four outcomes, and two of them are not answers

`valid` and `invalid` are conclusions. `skipped` means the step was not
attempted; `indeterminate` means it was attempted and the evidence did not
settle it. Neither ever reads as success, and an interface that renders them as
a green tick is misreporting.

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

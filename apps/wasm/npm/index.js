// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

// The browser module, wrapped so that a page imports it rather than reaching for
// a global.
//
// Nothing here takes a verification decision. It boots the WebAssembly module,
// hands it the proof and the trust material, and returns the canonical report
// unchanged, exactly as the command line adapter does.

// The Go runtime shim publishes globalThis.Go as a side effect. It ships in this
// package rather than being fetched, because it is version-locked to the module
// it accompanies: a shim from a different Go toolchain fails at runtime in ways
// that are tedious to diagnose.
import './wasm_exec.js';

/** @type {Promise<any> | null} */
let booting = null;

/**
 * boot instantiates the module once per page, however many verifiers are made.
 */
function boot(wasmUrl) {
  booting ??= (async () => {
    const go = new globalThis.Go();

    const instance = await instantiate(wasmUrl, go.importObject);

    // The Go program blocks forever so that its exports stay callable, so this
    // promise never resolves. It is still worth catching: a panic during start
    // up would otherwise surface only as an unhandled rejection.
    go.run(instance).catch((cause) => {
      throw new Error('the Sealway verifier stopped unexpectedly', { cause });
    });

    if (!globalThis.sealwayVerifier) {
      throw new Error('the Sealway verifier did not publish its API');
    }

    return globalThis.sealwayVerifier;
  })();

  return booting;
}

async function instantiate(wasmUrl, importObject) {
  const response = await fetch(wasmUrl);
  if (!response.ok) {
    throw new Error(`cannot load the verifier from ${wasmUrl}: HTTP ${response.status}`);
  }

  try {
    const result = await WebAssembly.instantiateStreaming(response, importObject);

    return result.instance;
  } catch {
    // Streaming instantiation requires the server to send
    // Content-Type: application/wasm, and some static hosts do not. Buffering
    // the module works regardless, at the cost of holding it in memory twice.
    const buffered = await fetch(wasmUrl);
    const result = await WebAssembly.instantiate(await buffered.arrayBuffer(), importObject);

    return result.instance;
  }
}

/**
 * loadTrustMaterial reads the European publications from a mirror.
 *
 * A mirror is a transport and never an authority: it serves the official signed
 * documents unchanged and the module verifies the European signatures itself
 * against the anchor it ships. A stale or hostile mirror can withhold or delay
 * material; it cannot invent a qualified service.
 */
async function loadTrustMaterial(baseUrl, territories) {
  const base = String(baseUrl).replace(/\/+$/, '');

  const read = async (path) => {
    const response = await fetch(`${base}/${path}`);
    if (!response.ok) {
      throw new Error(`${base}/${path}: HTTP ${response.status}`);
    }

    return new Uint8Array(await response.arrayBuffer());
  };

  const lists = {};

  const [lotl, ...loaded] = await Promise.all([
    read('lotl.xml'),
    ...territories.map((t) => read(`lists/${t.toLowerCase()}.xml`)),
  ]);

  territories.forEach((t, i) => {
    lists[t.toUpperCase()] = loaded[i];
  });

  return { lotl, lists };
}

/** toBytes accepts whatever a page is holding. */
async function toBytes(input) {
  if (input instanceof Uint8Array) {
    return input;
  }

  if (input instanceof ArrayBuffer) {
    return new Uint8Array(input);
  }

  if (typeof input?.arrayBuffer === 'function') {
    return new Uint8Array(await input.arrayBuffer());
  }

  throw new TypeError('expected a File, Blob, ArrayBuffer or Uint8Array');
}

/**
 * createVerifier boots the module and returns something a page can call.
 *
 * Supply trust material through trustBaseUrl or trust to have qualified eIDAS
 * status established. Without it the verifier reports qualification as
 * indeterminate: it will not answer a question it has no authenticated evidence
 * for, and will not treat the timestamp issuer's own claim as an answer.
 */
export async function createVerifier(options = {}) {
  const {
    wasmUrl = new URL('./sealway.wasm', import.meta.url),
    trust = null,
    trustBaseUrl = null,
    territories = ['ES'],
  } = options;

  const api = await boot(wasmUrl);

  let material = trust;

  if (!material && trustBaseUrl) {
    material = await loadTrustMaterial(trustBaseUrl, territories);
  }

  // Loading a national list on demand rather than up front. Every list the
  // European Union publishes comes to about 25 MB, and a proof needs exactly
  // one of them: the one covering the authority that stamped it.
  const loaded = new Map(Object.entries(material?.lists ?? {}));

  async function withTerritory(territory) {
    if (!material || !territory || loaded.has(territory)) {
      return material;
    }

    if (!trustBaseUrl) {
      return material;
    }

    try {
      const base = String(trustBaseUrl).replace(/\/+$/, '');
      const response = await fetch(`${base}/lists/${territory.toLowerCase()}.xml`);
      if (!response.ok) {
        return material;
      }

      loaded.set(territory, new Uint8Array(await response.arrayBuffer()));
      material = { ...material, lists: Object.fromEntries(loaded) };
    } catch {
      // A list that cannot be fetched leaves qualified status undetermined,
      // which the report says. It is not a reason to abandon the verification.
    }

    return material;
  }

  return {
    /** The report contract this build produces. */
    schemaVersion: api.schemaVersion,

    /** Whether qualified eIDAS status can be established at all. */
    hasTrustMaterial: Boolean(material),

    /**
     * verify checks a proof bundle and resolves with the canonical report.
     *
     * A proof that does not hold resolves normally, with a result of "invalid".
     * The promise rejects only on an operational failure, such as an archive
     * that cannot be read — which is a tool failure and not a verdict.
     */
    async verify(input, { verifyAnchors = false, timeoutSeconds = 20, sources, anchorEndpoints } = {}) {
      const bytes = await toBytes(input);

      return JSON.parse(await api.verify(bytes, {
        verifyAnchors,
        timeoutSeconds,
        anchorEndpoints,
        trust: material,
        sources: await toSourceList(sources),
      }));
    },

    /**
     * verifyTimestamp checks a bare RFC 3161 artifact on its own.
     *
     * The token may be a File, bytes, or the base64 or hexadecimal text people
     * paste. The report carries only the timestamp section: a token is a
     * statement about a digest and a moment, and nothing about a proof, its
     * files or its anchors is present to report on.
     */
    async verifyTimestamp(token, { imprint, chain, revocation, timeoutSeconds = 20 } = {}) {
      const artifact = typeof token === 'string' ? token : await toBytes(token);

      // Fetch the list covering whoever signed this, rather than all of them.
      const trust = await withTerritory(await api.requiredTerritory(artifact).catch(() => null));

      return JSON.parse(await api.verifyTimestamp(artifact, {
        timeoutSeconds,
        trust,
        imprint,
        chain,
        revocation,
      }));
    },

    /**
     * inspectTimestamp decodes a token without judging it. Reading a token and
     * believing it are different acts; verifyTimestamp is the second.
     */
    async inspectTimestamp(token) {
      const artifact = typeof token === 'string' ? token : await toBytes(token);

      return JSON.parse(await api.inspectTimestamp(artifact));
    },

    /**
     * requiredTerritory names the national Trusted List a token needs, for a
     * host deciding which one to serve.
     */
    async requiredTerritory(token) {
      const artifact = typeof token === 'string' ? token : await toBytes(token);

      return api.requiredTerritory(artifact);
    },

    /**
     * verifyMerkle answers a question about the Merkle profile alone: rebuild a
     * root from digests, or check that one leaf belongs to a tree.
     */
    async verifyMerkle(input) {
      return JSON.parse(await api.verifyMerkle(input));
    },
  };
}

/** toSourceList reads the original files a caller supplied beside a certificate. */
async function toSourceList(files) {
  if (!files?.length) {
    return null;
  }

  return Promise.all([...files].map(async (f) => ({
    name: f.name ?? '',
    content: await toBytes(f),
  })));
}

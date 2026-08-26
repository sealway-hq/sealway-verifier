// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

/** The outcome of a single verification step. */
export type Status = 'valid' | 'invalid' | 'skipped' | 'indeterminate';

/** The aggregated outcome of a verification run. */
export type Result = 'complete_valid' | 'partial_valid' | 'invalid';

export interface Check {
  id: string;
  title: string;
  status: Status;
  /** Always states why, for any step that did not simply succeed. */
  message: string;
  /**
   * Whether the step counts towards a complete verification. False for steps
   * documented as outside the scope of this version, so that skipping them does
   * not downgrade the result.
   */
  affects_completeness: boolean;
  details?: Record<string, string>;
}

export interface Section {
  id: string;
  title: string;
  checks: Check[];
}

export interface Report {
  schema_version: string;
  result: Result;
  summary: {
    total: number;
    valid: number;
    invalid: number;
    skipped: number;
    indeterminate: number;
    skipped_affecting_completeness: number;
    explanation: string;
  };
  certificate?: {
    public_id?: string;
    title?: string;
    item_count?: number;
  };
  sections: Section[];
}

/** Trust material: the official signed European documents, unchanged. */
export interface TrustMaterial {
  lotl: Uint8Array;
  lists: Record<string, Uint8Array>;
}

export interface CreateVerifierOptions {
  /**
   * Where to load the WebAssembly module from. Defaults to the copy shipped in
   * this package, resolved relative to it.
   */
  wasmUrl?: string | URL;
  /** Trust material already in hand. Takes precedence over trustBaseUrl. */
  trust?: TrustMaterial | null;
  /**
   * A mirror serving lotl.xml and lists/<territory>.xml. The European
   * signatures are verified here against the anchor this module ships, so the
   * mirror carries the bytes without becoming an authority.
   */
  trustBaseUrl?: string | null;
  /** Which national lists to load. Defaults to ['ES']. */
  territories?: string[];
}

export interface VerifyOptions {
  /**
   * Read the public blockchain anchors. Off by default: the public endpoints
   * may refuse a cross-origin request, in which case the anchor checks are
   * reported as skipped rather than failed.
   */
  verifyAnchors?: boolean;
  /** Bounds every network operation. Defaults to 20. */
  timeoutSeconds?: number;
}

export interface Verifier {
  /** The report contract this build produces. */
  readonly schemaVersion: string;
  /** Whether qualified eIDAS status can be established at all. */
  readonly hasTrustMaterial: boolean;
  /**
   * Checks a proof bundle and resolves with the canonical report.
   *
   * A proof that does not hold resolves normally, with a result of 'invalid'.
   * The promise rejects only on an operational failure, such as an archive that
   * cannot be read — which is a tool failure and not a verdict on the proof.
   */
  verify(
    input: File | Blob | ArrayBuffer | Uint8Array,
    options?: VerifyOptions,
  ): Promise<Report>;
}

/**
 * Boots the verifier. The WebAssembly module is instantiated once per page,
 * however many verifiers are created.
 *
 * Without trust material, qualified eIDAS status is reported as indeterminate:
 * the verifier will not answer a question it has no authenticated evidence for.
 */
export function createVerifier(options?: CreateVerifierOptions): Promise<Verifier>;

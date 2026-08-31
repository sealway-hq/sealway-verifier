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
  certificate?: CertificateSummary;
  sections: Section[];
}

/** What the certificate says about the proof it carries. */
export interface CertificateSummary {
  public_id?: string;
  schema_version?: string;
  title?: string;
  category?: string;
  hash_algorithm?: string;
  item_count: number;
  total_size_bytes: number;
  merkle_root?: string;
  accumulator_root?: string;
  created_at?: string;
  timestamped_at?: string;
}

/** A certificate, named the way a person reads one. */
export interface CertificateDetails {
  common_name?: string;
  subject?: string;
  issuer?: string;
  issuer_common_name?: string;
  serial_number?: string;
  signature_algorithm?: string;
  public_key_algorithm?: string;
  not_before?: string;
  not_after?: string;
  country?: string;
  organization?: string;
  sha256_fingerprint?: string;
  extended_key_usage?: string[];
  ocsp_servers?: string[];
  crl_distribution_points?: string[];
  issuer_urls?: string[];
}

/** What a timestamp says about itself, decoded and no more. */
export interface TimestampDetails {
  version: number;
  policy_oid?: string;
  serial_number?: string;
  gen_time?: string;
  accuracy?: string;
  ordering: boolean;
  nonce?: string;
  message_imprint?: string;
  hash_algorithm?: string;
  response_status?: string;
  /**
   * Whether the token carries the ETSI statement claiming qualified status. It
   * is a claim by its issuer and never evidence: only an authenticated Trusted
   * List answers that question.
   */
  qualified_statement: boolean;
  signer?: CertificateDetails;
  certificates?: CertificateDetails[];
}

/** One step of an inclusion path, and the side the sibling sits on. */
export interface MerkleSibling {
  /** The sibling digest, as bytes or lower-case hexadecimal. */
  digest: Uint8Array | string;
  /**
   * Which side the sibling sits on. It is required: the profile folds
   * SHA-512(0x01 || left || right), so the side changes the resulting value.
   */
  position: 'left' | 'right';
}

/**
 * What to ask about the Merkle profile: supply `leaves` to rebuild a root, or
 * `leaf` with its `path` and `root` to check an inclusion. Not both.
 */
export interface MerkleInput {
  leaves?: Array<Uint8Array | string>;
  leaf?: Uint8Array | string;
  path?: MerkleSibling[];
  root?: Uint8Array | string;
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

/** An original file supplied beside a certificate. */
export interface SourceFile {
  name: string;
  content: Uint8Array;
}

export interface VerifyOptions {
  /**
   * Original files certified by the proof, supplied beside it rather than zipped
   * under `files/`. Accepted beside a certificate and beside a bundle alike: an
   * archive that ships a certificate and nothing else carries no files of its
   * own. Without them the file dependent steps are reported as skipped and the
   * run is partial.
   *
   * Only the file name is read, so `files/report.pdf` designates the same
   * certified item as `report.pdf`. A file whose name the archive already
   * carries is refused rather than resolved.
   */
  sources?: Array<File | SourceFile>;
  /**
   * Endpoints to read the public chains from, as `{network: url}`. The public
   * defaults may refuse a cross-origin request; this points at one that will
   * not.
   */
  anchorEndpoints?: Record<string, string>;
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

  /**
   * Checks a bare RFC 3161 timestamp on its own.
   *
   * The token may be a File, bytes, or the base64 or hexadecimal text people
   * paste. The report carries only the timestamp section: a token is a statement
   * about a digest and a moment, and nothing about a proof, its files or its
   * anchors is present to report on.
   *
   * Supply `imprint` to have the token compared with a digest you expect it to
   * stamp. Without it the imprint is read and reported but compared with
   * nothing, because what a token *should* cover is a question only the caller
   * can ask.
   */
  verifyTimestamp(
    token: File | Blob | ArrayBuffer | Uint8Array | string,
    options?: {
      imprint?: Uint8Array | string;
      chain?: Uint8Array;
      revocation?: Array<Uint8Array>;
      timeoutSeconds?: number;
    },
  ): Promise<Report>;

  /**
   * Decodes a token without judging it. Reading a token and believing it are
   * different acts; `verifyTimestamp` is the second.
   */
  inspectTimestamp(
    token: File | Blob | ArrayBuffer | Uint8Array | string,
  ): Promise<TimestampDetails>;

  /**
   * Names the national Trusted List a token needs, so a host serves one list
   * rather than the twenty-five megabytes the European Union publishes.
   *
   * Empty when the signing certificate names no country, which is also why
   * qualified status would be left undetermined.
   */
  requiredTerritory(
    token: File | Blob | ArrayBuffer | Uint8Array | string,
  ): Promise<string>;

  /**
   * Answers a question about the Merkle profile alone: rebuild a root from
   * digests, or check that one leaf belongs to a tree.
   */
  verifyMerkle(input: MerkleInput): Promise<Report>;
}

/**
 * Boots the verifier. The WebAssembly module is instantiated once per page,
 * however many verifiers are created.
 *
 * Without trust material, qualified eIDAS status is reported as indeterminate:
 * the verifier will not answer a question it has no authenticated evidence for.
 */
export function createVerifier(options?: CreateVerifierOptions): Promise<Verifier>;

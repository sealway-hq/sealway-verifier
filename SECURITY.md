# Security policy

## Reporting a vulnerability

Please report security issues privately through
[GitHub Security Advisories](https://github.com/sealway-hq/sealway-verifier/security/advisories/new)
rather than in a public issue.

Please include what you need to demonstrate the problem: the affected version,
the input that triggers it and what you observed. If the report involves a proof,
a synthetic one is preferable to a real customer proof.

## What is in scope

This repository is a verifier. The findings that matter most are the ones that
break what it is for:

- **False acceptance.** Any input that makes the verifier report `COMPLETE_VALID`
  or `PARTIAL_VALID` for a proof that does not actually hold: a forged Merkle
  path, a timestamp that does not cover the proof root, an anchor whose payload
  is not the accumulator root, a digest comparison that can be bypassed.
- **Overclaiming.** Any case where the report asserts more than was verified, for
  example presenting a skipped step as successful, or presenting a valid CMS
  signature as evidence of a trusted or qualified timestamp.
- **Memory or process safety on untrusted input.** A crash, panic, unbounded
  allocation or unbounded run time triggered by a hostile archive, certificate,
  manifest or endpoint response.
- **Escaping the input.** Anything that makes the verifier read or write a path
  it was not given, follow a link out of a supplied directory, or send a request
  somewhere a manifest chose.

## What is not in scope

- A proof correctly reported as `INVALID`. That is the tool working.
- A step reported as `SKIPPED` because evidence was missing or a network was
  unreachable. Those are documented outcomes, and the README lists them.
- The absence of EU trusted-list validation and of document signature
  verification. Both are documented scope limits of this version, and both are
  reported as skipped rather than assumed.
- Availability of the public blockchain endpoints. They are third-party services,
  they are configurable, and an unreachable one skips a check rather than failing
  it.

## Design notes relevant to a review

- The certificate is the only authoritative input. The loose copies a bundle may
  carry are never a fallback: if that ever stops being true, it is a finding.
- Archives are never extracted to disk.
- The verifier holds no credential, contacts no Sealway service, and every
  endpoint it does contact is unauthenticated and replaceable.
- Fuzz targets cover manifest parsing, digest decoding, Merkle proof
  verification, timestamp parsing, archive reading and both verification entry
  points. Untrusted input must never panic.

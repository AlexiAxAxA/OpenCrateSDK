# Security review of the SDK preview

Status: **internal review in progress; no independent audit**.
This document records the checks performed on the `0.0.1` preview candidate.

The `0.0.2` preview keeps the `OCSB1` implementation and public API from
`0.0.1`; its dependency is now `oc-crypto = 0.0.2`. Local checks covered the
SDK round trip and binding failures with the new dependency, plus a fresh
registry consumer through `opencrate::app_data`. These checks do not replace an
independent review of the envelope and key lifecycle.

The separate experimental C ABI in `ffi/` adds raw-pointer and caller-buffer
contracts. Python, Java and C++ smoke programs must be treated as integration
checks, not an audit of the language runtimes or key storage. The ABI accepts
only bounded inputs, copies them before output writes, catches Rust panics and
returns generic cryptographic errors; invalid foreign pointers remain caller
undefined behavior. See [foreign-language usage](foreign-languages.md).

The 0.0.5 release uses MPL-2.0 and fixes DH encoding validation through
`oc-crypto = "=0.0.5"`. Noncanonical recipients are rejected before an unusable
envelope can be returned. The core also checks ephemeral encodings before DH/KDF
and explicitly redacts both private hybrid-key fields in Debug output. The OCSB1
layout, KDF and public API stay unchanged.

New local checks cover 10,928 envelope bit mutations, 1,366 truncations, ten
appended-byte checks, purpose/context binding, low-order and noncanonical
recipients, the 16 MiB boundary, and entropy failure on either RNG draw. Eight
Python ABI tests exercise the actual native library with valid buffers. Tests,
Clippy, Rustdoc and license/advisory/source checks passed locally. The core's
[review notes](https://github.com/AlexiAxAxA/OpenCrate/blob/main/docs/review-2026-09-26.md)
describe ten regression tests, the bounded property checks and the limits of
the additional audit.

## Properties checked locally

- The SDK imports `oc-crypto = 0.0.1` from the registry in a standalone Cargo
  project. The separate repository has no path dependency on the Open Crate
  checkout or Close Crate source.
- The envelope parser checks magic and minimum/maximum length before slicing or
  allocating its ciphertext copy. The plaintext limit is 16 MiB.
- The core authenticates ciphertext and caller-supplied context. The SDK uses a
  dedicated domain prefix plus a length-prefixed, nonempty purpose.
- Tests reject a wrong recipient, purpose, context, modified ciphertext,
  malformed envelope and a small-order public key. Tests also cover a valid
  round trip.
- SDK code forbids unsafe Rust and passes Clippy with warnings denied. The
  returned plaintext buffer zeroizes on drop. OS entropy errors return an
  error without returning a sealed envelope.

## Boundaries and remaining work

The SDK does not verify who owns a recipient public key, protect a private
key at rest, authorize a caller, enforce a policy, or revoke access. Consumers
must provide those facilities. The example's temporary key is for learning,
not persistent storage.

Hosted [CI run 35913875127](https://github.com/AlexiAxAxA/OpenCrateSDK/actions/runs/35913875127)
passed Linux and Windows tests, Clippy, Rustdoc, the example, and a separate
`cargo-deny` check for licenses, bans, advisories and sources on commit
`f0891b5`.

Before a stable release: review the `OCSB1` wire and domain separation with an
independent cryptography reviewer, add a frozen compatibility vector and
versioning policy, and obtain feedback from an integrator outside the project.
These checks do not establish production security.

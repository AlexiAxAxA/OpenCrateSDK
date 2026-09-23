# Security review of the SDK preview

Status: **internal review in progress; no independent audit or release claim**.
This document records the checks performed on this source-only candidate.

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

# Open Crate SDK

A Rust SDK for small encrypted application values, built on the published
[`oc-crypto`](https://crates.io/crates/oc-crypto) core. The input can be JSON,
a message, or binary data. The result is an authenticated `OCSB1` envelope,
not a `.cc` document.

This repository is a **source-only preview**. Its API and envelope have not
been released or independently audited. It does not issue leases, revoke
access, or enforce an access policy.

## Try it

Install Rust, then from this repository:

```sh
cargo run --locked --example json-message
```

The example seals JSON-shaped bytes for one recipient, opens them, and checks
the result. In your own project, use a path dependency while the SDK is a
preview:

```toml
[dependencies]
opencrate-sdk = { path = "../OpenCrateSDK" }
```

```rust
use opencrate_sdk::{generate_recipient, open_bytes, recipient_public, seal_bytes};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secret = generate_recipient()?;
    let envelope = seal_bytes(
        &recipient_public(&secret),
        "com.example.invoice.v1",
        b"tenant-7",
        br#"{"total":42}"#,
    )?;
    let plaintext = open_bytes(&secret, "com.example.invoice.v1", b"tenant-7", &envelope)?;
    assert_eq!(&*plaintext, br#"{"total":42}"#);
    Ok(())
}
```

The example generates a temporary key. A real application must protect and
reload the same recipient secret, distribute an authentic public key, and
persist the envelope. `X25519Secret` is re-exported for a key-store adapter;
its `from_bytes` and `expose` methods are explicit import/export boundaries.
Keep the application-specific `purpose` and `context` stable. Neither is stored
in the envelope, and a mismatch prevents opening.

The input limit is 16 MiB. For large files, multiple recipients, author
signatures and policy-controlled document access, use the
[Open Crate core](https://github.com/AlexiAxAxA/OpenCrate) and its `.cc` format.
The [architecture](docs/architecture.md) explains the separation. The
[security review](docs/security-review.md) records what has and has not been
checked for this preview.

## License

The [Open Crate Community License 1.0](LICENSE-OPENCRATE) applies to this SDK
and its Open Crate core dependency. See the complete terms in the license file.

// SPDX-License-Identifier: MPL-2.0
//! Demonstrate the SDK with JSON-shaped bytes, not a `.cc` file.
use opencrate_sdk::{generate_recipient, open_bytes, recipient_public, seal_bytes};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let recipient = generate_recipient()?;
    let envelope = seal_bytes(
        &recipient_public(&recipient),
        "com.example.invoice.v1",
        b"tenant-7",
        br#"{"total":42}"#,
    )?;
    let opened = open_bytes(&recipient, "com.example.invoice.v1", b"tenant-7", &envelope)?;
    assert_eq!(&*opened, br#"{"total":42}"#);
    println!("JSON bytes sealed and authenticated; envelope length: {}", envelope.len());
    Ok(())
}

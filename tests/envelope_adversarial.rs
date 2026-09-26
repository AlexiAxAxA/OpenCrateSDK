// SPDX-License-Identifier: MPL-2.0
use opencrate_sdk::{Error, generate_recipient, open_bytes, recipient_public, seal_bytes};

#[test]
fn noncanonical_recipient_fails_before_returning_an_unopenable_envelope() -> Result<(), Error> {
    let key = generate_recipient()?;
    let mut alias = recipient_public(&key);
    alias[31] |= 0x80;
    assert!(seal_bytes(&alias, "test", b"context", b"secret").is_err());
    Ok(())
}

#[test]
fn every_envelope_bit_and_truncation_is_authenticated() -> Result<(), Error> {
    let key = generate_recipient()?;
    let public = recipient_public(&key);
    let purpose = "test.envelope.v1";
    let context = b"tenant:record";

    for size in [0, 1, 15, 16, 17, 31, 32, 63, 64, 257] {
        let plaintext = vec![0xa5; size];
        let envelope = seal_bytes(&public, purpose, context, &plaintext)?;
        assert_eq!(&*open_bytes(&key, purpose, context, &envelope)?, &plaintext);

        for (index, byte) in envelope.iter().enumerate() {
            for bit in 0..8 {
                let mut damaged = envelope.clone();
                if let Some(target) = damaged.get_mut(index) {
                    *target = byte ^ (1 << bit);
                }
                assert!(open_bytes(&key, purpose, context, &damaged).is_err());
            }
        }
        for length in 0..envelope.len() {
            if let Some(prefix) = envelope.get(..length) {
                assert!(open_bytes(&key, purpose, context, prefix).is_err());
            }
        }
        let mut appended = envelope.clone();
        appended.push(0);
        assert!(open_bytes(&key, purpose, context, &appended).is_err());
    }
    Ok(())
}

#[test]
fn purpose_limits_count_utf8_bytes_and_bind_the_whole_value() -> Result<(), Error> {
    let key = generate_recipient()?;
    let public = recipient_public(&key);
    let purpose = "é".repeat(64);
    let envelope = seal_bytes(&public, &purpose, b"", b"data")?;
    assert_eq!(&*open_bytes(&key, &purpose, b"", &envelope)?, b"data");
    assert!(matches!(seal_bytes(&public, &(purpose.clone() + "x"), b"", b"data"),
                     Err(Error::InvalidPurpose)));
    assert!(matches!(open_bytes(&key, "", b"", &envelope), Err(Error::InvalidPurpose)));
    assert!(open_bytes(&key, &"e".repeat(128), b"", &envelope).is_err());
    assert!(open_bytes(&key, &purpose, b"changed", &envelope).is_err());
    Ok(())
}

#[test]
fn low_order_keys_are_rejected_on_both_sides() -> Result<(), Error> {
    let key = generate_recipient()?;
    let public = recipient_public(&key);
    let envelope = seal_bytes(&public, "test.key.v1", b"", b"secret")?;
    for first in [0, 1] {
        let mut low_order = [0; 32];
        if let Some(byte) = low_order.first_mut() {
            *byte = first;
        }
        assert!(seal_bytes(&low_order, "test.key.v1", b"", b"secret").is_err());
        let mut damaged = envelope.clone();
        if let Some(enc) = damaged.get_mut(5..37) {
            enc.copy_from_slice(&low_order);
        }
        assert!(open_bytes(&key, "test.key.v1", b"", &damaged).is_err());
    }
    Ok(())
}

#[test]
fn size_limit_accepts_the_boundary_and_rejects_one_extra_byte() -> Result<(), Error> {
    const LIMIT: usize = 16 * 1024 * 1024;
    let key = generate_recipient()?;
    let public = recipient_public(&key);
    let plaintext = vec![0x5a; LIMIT];
    let mut envelope = seal_bytes(&public, "test.limit.v1", b"object", &plaintext)?;
    assert_eq!(&*open_bytes(&key, "test.limit.v1", b"object", &envelope)?, &plaintext);
    envelope.push(0);
    assert!(matches!(open_bytes(&key, "test.limit.v1", b"object", &envelope),
                     Err(Error::TooLarge)));
    let too_large = vec![0; LIMIT + 1];
    assert!(matches!(seal_bytes(&public, "test.limit.v1", b"object", &too_large),
                     Err(Error::TooLarge)));
    Ok(())
}

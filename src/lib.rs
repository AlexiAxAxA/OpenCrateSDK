// SPDX-License-Identifier: MPL-2.0
//! Small host-side SDK for encrypting application data without a `.cc` container.
//!
//! This API seals bytes to one X25519 recipient. It does not issue leases,
//! evaluate access rules, or provide revocation. The application protects the
//! recipient's private key and chooses a stable purpose and context.
#![forbid(unsafe_code)]

use getrandom::rand_core::{Infallible, TryCryptoRng, TryRng};
use oc_crypto::{CryptoError, seal::SealedBlob};
use zeroize::{Zeroize, Zeroizing};

/// Recipient key, redacted in `Debug`. The application stores and backs it up.
pub use oc_crypto::secret::X25519Secret;

const MAGIC: &[u8; 5] = b"OCSB1";
const INFO_PREFIX: &[u8] = b"OpenCrate SDK/v1/sealed-bytes\0";
const MAX_PURPOSE: usize = 128;
const MAX_BYTES: usize = 16 * 1024 * 1024;
const ENVELOPE_OVERHEAD: usize = 5 + 32 + 24 + 16;

/// An SDK failure; diagnostics contain no key or plaintext bytes.
#[derive(Debug)]
pub enum Error {
    /// Purpose is empty or exceeds 128 UTF-8 bytes.
    InvalidPurpose,
    /// Plaintext or envelope exceeds the 16 MiB payload limit.
    TooLarge,
    /// Envelope magic, length, or field layout is invalid.
    InvalidEnvelope,
    /// The operating system could not supply random bytes.
    Entropy,
    /// Key agreement or authentication failed in the core.
    Crypto(CryptoError),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidPurpose => f.write_str("purpose must be 1 to 128 bytes"),
            Self::TooLarge => f.write_str("data exceeds the 16 MiB SDK limit"),
            Self::InvalidEnvelope => f.write_str("invalid sealed-data envelope"),
            Self::Entropy => f.write_str("system randomness is unavailable"),
            Self::Crypto(_) => f.write_str("sealed-data cryptographic operation failed"),
        }
    }
}

impl std::error::Error for Error {}

/// Generate a recipient key using the operating system's random source.
/// The caller owns storage, backup and access to this key.
pub fn generate_recipient() -> Result<X25519Secret, Error> {
    let mut bytes = [0u8; 32];
    if getrandom::fill(&mut bytes).is_err() {
        bytes.zeroize();
        return Err(Error::Entropy);
    }
    let secret = X25519Secret::from_bytes(bytes);
    bytes.zeroize();
    Ok(secret)
}

/// Derive the public key that a sender needs to seal data to this recipient.
#[must_use]
pub fn recipient_public(secret: &X25519Secret) -> [u8; 32] {
    oc_crypto::seal::x25519_public(secret)
}

/// Seal an application value as an `OCSB1` envelope.
///
/// `purpose` separates different uses (for example `com.example.invoice.v1`).
/// `context` binds the envelope to an application object or tenant and must be
/// supplied unchanged when opening. Neither value is stored in the envelope.
/// An empty context is allowed only when the application has no binding to make.
pub fn seal_bytes(
    recipient: &[u8; 32],
    purpose: &str,
    context: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    seal_bytes_with_rng(recipient, purpose, context, plaintext, &mut FallibleOsRng::default())
}

fn seal_bytes_with_rng(
    recipient: &[u8; 32],
    purpose: &str,
    context: &[u8],
    plaintext: &[u8],
    rng: &mut FallibleOsRng,
) -> Result<Vec<u8>, Error> {
    let info = info(purpose)?;
    if plaintext.len() > MAX_BYTES {
        return Err(Error::TooLarge);
    }
    let result = oc_crypto::seal::seal(recipient, &info, context, plaintext, rng);
    if rng.failed {
        return Err(Error::Entropy);
    }
    let blob = result.map_err(Error::Crypto)?;
    if blob.enc.len() != 32 || blob.ct.len() != plaintext.len().saturating_add(16) {
        return Err(Error::InvalidEnvelope);
    }
    let mut out = Vec::with_capacity(ENVELOPE_OVERHEAD.saturating_add(plaintext.len()));
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&blob.enc);
    out.extend_from_slice(&blob.nonce);
    out.extend_from_slice(&blob.ct);
    Ok(out)
}

/// Authenticate and open an `OCSB1` envelope.
///
/// The returned buffer is zeroized when dropped. A wrong key, purpose, context,
/// or modified ciphertext fails authentication and never returns plaintext.
pub fn open_bytes(
    secret: &X25519Secret,
    purpose: &str,
    context: &[u8],
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let info = info(purpose)?;
    if envelope.len() > MAX_BYTES.saturating_add(ENVELOPE_OVERHEAD) {
        return Err(Error::TooLarge);
    }
    if envelope.len() < ENVELOPE_OVERHEAD || !envelope.starts_with(MAGIC) {
        return Err(Error::InvalidEnvelope);
    }
    let enc_end = MAGIC.len().saturating_add(32);
    let nonce_end = enc_end.saturating_add(24);
    let nonce: [u8; 24] = envelope
        .get(enc_end..nonce_end)
        .ok_or(Error::InvalidEnvelope)?
        .try_into()
        .map_err(|_| Error::InvalidEnvelope)?;
    let blob = SealedBlob {
        enc: envelope.get(MAGIC.len()..enc_end).ok_or(Error::InvalidEnvelope)?.to_vec(),
        nonce,
        ct: envelope.get(nonce_end..).ok_or(Error::InvalidEnvelope)?.to_vec(),
    };
    oc_crypto::seal::open(secret, &blob, &info, context).map_err(Error::Crypto)
}

fn info(purpose: &str) -> Result<Vec<u8>, Error> {
    let bytes = purpose.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_PURPOSE {
        return Err(Error::InvalidPurpose);
    }
    let mut info =
        Vec::with_capacity(INFO_PREFIX.len().saturating_add(1).saturating_add(bytes.len()));
    info.extend_from_slice(INFO_PREFIX);
    info.push(u8::try_from(bytes.len()).map_err(|_| Error::InvalidPurpose)?);
    info.extend_from_slice(bytes);
    Ok(info)
}

/// Bridge OS entropy errors to the core's infallible RNG trait.
/// Once entropy fails, zero-fill subsequent requests. `seal_bytes` checks the
/// flag before using any result, so this intermediate output cannot escape.
#[derive(Default)]
struct FallibleOsRng {
    failed: bool,
    // Test-only entropy fault injection; production uses OS entropy.
    #[cfg(test)]
    fail_after: Option<usize>,
    #[cfg(test)]
    draws: usize,
}

impl TryRng for FallibleOsRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        #[cfg(test)]
        {
            if self.fail_after == Some(self.draws) {
                self.failed = true;
            }
            self.draws = self.draws.saturating_add(1);
        }
        if self.failed || getrandom::fill(dst).is_err() {
            self.failed = true;
            dst.fill(0);
        }
        Ok(())
    }
}

impl TryCryptoRng for FallibleOsRng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_failure_on_either_draw_never_releases_an_envelope() -> Result<(), Error> {
        let secret = X25519Secret::from_bytes([0x11; 32]);
        let public = recipient_public(&secret);
        for failed_draw in 0..=1 {
            let mut rng = FallibleOsRng { fail_after: Some(failed_draw), ..Default::default() };
            assert!(matches!(
                seal_bytes_with_rng(&public, "review", b"tenant", b"sentinel", &mut rng),
                Err(Error::Entropy)
            ));
            let mut destination = [0x5a; 32];
            assert!(rng.try_fill_bytes(&mut destination).is_ok());
            assert_eq!(destination, [0; 32]);
            assert!(matches!(
                seal_bytes_with_rng(&public, "review", b"tenant", b"sentinel", &mut rng),
                Err(Error::Entropy)
            ));
        }
        let mut control = FallibleOsRng { fail_after: Some(2), ..Default::default() };
        let envelope = seal_bytes_with_rng(&public, "review", b"tenant", b"sentinel", &mut control)?;
        assert!(!control.failed);
        assert_eq!(open_bytes(&secret, "review", b"tenant", &envelope)?.as_slice(), b"sentinel");
        Ok(())
    }

    #[test]
    fn round_trip_and_binding_failures() -> Result<(), Error> {
        let recipient = generate_recipient()?;
        let public = recipient_public(&recipient);
        let envelope = seal_bytes(&public, "example.invoice.v1", b"tenant-7", br#"{"total":42}"#)?;
        assert_eq!(
            &*open_bytes(&recipient, "example.invoice.v1", b"tenant-7", &envelope)?,
            br#"{"total":42}"#
        );

        let other = generate_recipient()?;
        assert!(open_bytes(&other, "example.invoice.v1", b"tenant-7", &envelope).is_err());
        assert!(open_bytes(&recipient, "example.note.v1", b"tenant-7", &envelope).is_err());
        assert!(open_bytes(&recipient, "example.invoice.v1", b"tenant-8", &envelope).is_err());
        let mut damaged = envelope.clone();
        let last = damaged.len() - 1;
        if let Some(byte) = damaged.get_mut(last) {
            *byte ^= 1;
        }
        assert!(open_bytes(&recipient, "example.invoice.v1", b"tenant-7", &damaged).is_err());
        assert!(open_bytes(&recipient, "example.invoice.v1", b"tenant-7", b"OCSB1").is_err());
        assert!(seal_bytes(&public, "", b"tenant-7", b"data").is_err());
        assert!(seal_bytes(&[0; 32], "example.invoice.v1", b"tenant-7", b"data").is_err());
        let mut wrong_magic = envelope.clone();
        if let Some(byte) = wrong_magic.first_mut() {
            *byte ^= 1;
        }
        assert!(open_bytes(&recipient, "example.invoice.v1", b"tenant-7", &wrong_magic).is_err());
        Ok(())
    }
}

//! Experimental C ABI for the Open Crate sealed-byte SDK.
//!
//! The pure Rust core and SDK keep their own safety rules. Raw-pointer handling
//! is isolated here. See `include/opencrate_ffi.h` for caller preconditions.

use opencrate_sdk::{
    Error, X25519Secret, generate_recipient, open_bytes, recipient_public, seal_bytes,
};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
};
use zeroize::{Zeroize, Zeroizing};

const KEY_LEN: usize = 32;
const MAX_DATA: usize = 16 * 1024 * 1024;
const MAX_ENVELOPE: usize = MAX_DATA + 77;
const MAX_PURPOSE: usize = 128;
const MAX_CONTEXT: usize = 64 * 1024;

const OK: i32 = 0;
const INVALID_ARGUMENT: i32 = 1;
const OUTPUT_TOO_SMALL: i32 = 2;
const INVALID_PURPOSE: i32 = 3;
const TOO_LARGE: i32 = 4;
const INVALID_ENVELOPE: i32 = 5;
const ENTROPY: i32 = 6;
const CRYPTO: i32 = 7;
const PANIC: i32 = 8;

fn status(error: Error) -> i32 {
    match error {
        Error::InvalidPurpose => INVALID_PURPOSE,
        Error::TooLarge => TOO_LARGE,
        Error::InvalidEnvelope => INVALID_ENVELOPE,
        Error::Entropy => ENTROPY,
        Error::Crypto(_) => CRYPTO,
    }
}

fn guard(operation: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(operation)).unwrap_or(PANIC)
}

/// ABI revision, independent of the `OCSB1` envelope version.
#[unsafe(no_mangle)]
pub extern "C" fn ocb_abi_version() -> u32 {
    1
}

/// Generate one secret/public recipient key pair into separate 32-byte buffers.
///
/// # Safety
/// Both pointers must designate writable, nonoverlapping 32-byte regions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ocb_generate_recipient(secret_out: *mut u8, public_out: *mut u8) -> i32 {
    guard(|| {
        if secret_out.is_null() || public_out.is_null() {
            return INVALID_ARGUMENT;
        }
        let secret = match generate_recipient() {
            Ok(secret) => secret,
            Err(error) => return status(error),
        };
        let public = recipient_public(&secret);
        // SAFETY: The caller promises distinct writable 32-byte regions.
        unsafe {
            ptr::copy_nonoverlapping(secret.expose().as_ptr(), secret_out, KEY_LEN);
            ptr::copy_nonoverlapping(public.as_ptr(), public_out, KEY_LEN);
        }
        OK
    })
}

/// Derive a public key from a 32-byte secret.
///
/// # Safety
/// The input and output must each designate 32 valid bytes and not overlap.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ocb_public_from_secret(secret: *const u8, public_out: *mut u8) -> i32 {
    guard(|| {
        if secret.is_null() || public_out.is_null() {
            return INVALID_ARGUMENT;
        }
        let mut bytes = [0u8; KEY_LEN];
        // SAFETY: The caller promises a readable 32-byte input.
        unsafe { ptr::copy_nonoverlapping(secret, bytes.as_mut_ptr(), KEY_LEN) };
        let key = X25519Secret::from_bytes(bytes);
        bytes.zeroize();
        let public = recipient_public(&key);
        // SAFETY: The caller promises a writable 32-byte output.
        unsafe { ptr::copy_nonoverlapping(public.as_ptr(), public_out, KEY_LEN) };
        OK
    })
}

/// Seal bytes into an `OCSB1` envelope.
///
/// # Safety
/// Every non-null input pointer must designate its stated readable length;
/// null is allowed only with length zero. `recipient` designates 32 bytes.
/// `written` designates a writable `size_t` and must not overlap other memory.
/// `output` designates `output_capacity` writable bytes when non-null and must
/// not overlap `written`. A null output with zero capacity queries the needed
/// size without sealing. Inputs are copied before the output is written.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ocb_seal(
    recipient: *const u8,
    purpose: *const u8,
    purpose_len: usize,
    context: *const u8,
    context_len: usize,
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_capacity: usize,
    written: *mut usize,
) -> i32 {
    guard(|| {
        if recipient.is_null() || written.is_null() || (output.is_null() && output_capacity != 0) {
            return INVALID_ARGUMENT;
        }
        // SAFETY: The caller promises an isolated writable size_t.
        unsafe { ptr::write(written, 0) };
        let purpose = match unsafe { read_purpose(purpose, purpose_len) } {
            Ok(value) => value,
            Err(code) => return code,
        };
        let context = match unsafe { read_copy(context, context_len, MAX_CONTEXT) } {
            Ok(value) => value,
            Err(code) => return code,
        };
        let input = match unsafe { read_copy(input, input_len, MAX_DATA) } {
            Ok(value) => Zeroizing::new(value),
            Err(code) => return code,
        };
        let required = input.len().saturating_add(77);
        if output.is_null() || output_capacity < required {
            unsafe { ptr::write(written, required) };
            return OUTPUT_TOO_SMALL;
        }
        let mut public = [0u8; KEY_LEN];
        // SAFETY: The caller promises a readable 32-byte public key.
        unsafe { ptr::copy_nonoverlapping(recipient, public.as_mut_ptr(), KEY_LEN) };
        let envelope = match seal_bytes(&public, &purpose, &context, &input) {
            Ok(value) => value,
            Err(error) => return status(error),
        };
        // SAFETY: Capacity was checked and output is writable and disjoint.
        unsafe {
            ptr::copy_nonoverlapping(envelope.as_ptr(), output, envelope.len());
            ptr::write(written, envelope.len());
        }
        OK
    })
}

/// Authenticate and open an `OCSB1` envelope.
///
/// # Safety
/// Pointer and ownership rules are the same as for `ocb_seal`; `secret`
/// designates 32 readable bytes. A size query is only an allocation hint: it
/// does not authenticate the envelope. Treat output as plaintext only on `OK`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ocb_open(
    secret: *const u8,
    purpose: *const u8,
    purpose_len: usize,
    context: *const u8,
    context_len: usize,
    envelope: *const u8,
    envelope_len: usize,
    output: *mut u8,
    output_capacity: usize,
    written: *mut usize,
) -> i32 {
    guard(|| {
        if secret.is_null() || written.is_null() || (output.is_null() && output_capacity != 0) {
            return INVALID_ARGUMENT;
        }
        unsafe { ptr::write(written, 0) };
        let purpose = match unsafe { read_purpose(purpose, purpose_len) } {
            Ok(value) => value,
            Err(code) => return code,
        };
        let context = match unsafe { read_copy(context, context_len, MAX_CONTEXT) } {
            Ok(value) => value,
            Err(code) => return code,
        };
        let envelope = match unsafe { read_copy(envelope, envelope_len, MAX_ENVELOPE) } {
            Ok(value) => value,
            Err(code) => return code,
        };
        if envelope.len() < 77 {
            return INVALID_ENVELOPE;
        }
        let required = envelope.len().saturating_sub(77);
        if output.is_null() || output_capacity < required {
            unsafe { ptr::write(written, required) };
            return OUTPUT_TOO_SMALL;
        }
        let mut bytes = [0u8; KEY_LEN];
        unsafe { ptr::copy_nonoverlapping(secret, bytes.as_mut_ptr(), KEY_LEN) };
        let key = X25519Secret::from_bytes(bytes);
        bytes.zeroize();
        let plaintext = match open_bytes(&key, &purpose, &context, &envelope) {
            Ok(value) => value,
            Err(error) => return status(error),
        };
        if !plaintext.is_empty() {
            if output.is_null() {
                return INVALID_ARGUMENT;
            }
            unsafe { ptr::copy_nonoverlapping(plaintext.as_ptr(), output, plaintext.len()) };
        }
        unsafe { ptr::write(written, plaintext.len()) };
        OK
    })
}

unsafe fn read_copy(pointer: *const u8, len: usize, maximum: usize) -> Result<Vec<u8>, i32> {
    if len > maximum || len > isize::MAX as usize {
        return Err(TOO_LARGE);
    }
    if len == 0 {
        return Ok(Vec::new());
    }
    if pointer.is_null() {
        return Err(INVALID_ARGUMENT);
    }
    // SAFETY: Pointer validity is an explicit C caller precondition.
    Ok(unsafe { std::slice::from_raw_parts(pointer, len) }.to_vec())
}

unsafe fn read_purpose(pointer: *const u8, len: usize) -> Result<String, i32> {
    if len == 0 || len > MAX_PURPOSE {
        return Err(INVALID_PURPOSE);
    }
    let bytes = unsafe { read_copy(pointer, len, MAX_PURPOSE) }?;
    String::from_utf8(bytes).map_err(|_| INVALID_PURPOSE)
}

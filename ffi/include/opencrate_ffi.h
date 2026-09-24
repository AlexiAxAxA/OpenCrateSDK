#ifndef OPENCRATE_FFI_H
#define OPENCRATE_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Preview ABI v1, 64-bit native processes. OCSB1 is a different version. */
enum {
    OCB_OK = 0,
    OCB_INVALID_ARGUMENT = 1,
    OCB_OUTPUT_TOO_SMALL = 2,
    OCB_INVALID_PURPOSE = 3,
    OCB_TOO_LARGE = 4,
    OCB_INVALID_ENVELOPE = 5,
    OCB_ENTROPY = 6,
    OCB_CRYPTO = 7,
    OCB_PANIC = 8,
    OCB_KEY_LEN = 32,
    OCB_MAX_PLAINTEXT = 16 * 1024 * 1024,
    OCB_ENVELOPE_OVERHEAD = 77,
    OCB_MAX_CONTEXT = 64 * 1024
};

uint32_t ocb_abi_version(void);
int32_t ocb_generate_recipient(uint8_t secret_out[32], uint8_t public_out[32]);
int32_t ocb_public_from_secret(const uint8_t secret[32], uint8_t public_out[32]);

/* All input pointers are readable for their stated lengths. NULL is accepted
 * only when length is zero. The key pointer always designates 32 bytes.
 * `written` is a writable size_t, disjoint from all other regions. Output is
 * writable for output_capacity bytes and disjoint from `written`. Inputs may
 * overlap output because the implementation copies them first.
 *
 * A NULL output with zero capacity returns OCB_OUTPUT_TOO_SMALL and sets
 * `written` to the needed capacity. This query does not encrypt or authenticate.
 * The caller owns all buffers; secret bytes must be protected and cleared by
 * the caller. On failure, output is untouched and `written` is normally zero
 * except on OCB_OUTPUT_TOO_SMALL. Treat output as valid only on OCB_OK.
 * `purpose` is nonempty UTF-8 (at most 128 bytes). `context` is at most 64 KiB.
 */
int32_t ocb_seal(const uint8_t recipient[32],
                 const uint8_t *purpose, size_t purpose_len,
                 const uint8_t *context, size_t context_len,
                 const uint8_t *input, size_t input_len,
                 uint8_t *output, size_t output_capacity, size_t *written);

int32_t ocb_open(const uint8_t secret[32],
                 const uint8_t *purpose, size_t purpose_len,
                 const uint8_t *context, size_t context_len,
                 const uint8_t *envelope, size_t envelope_len,
                 uint8_t *output, size_t output_capacity, size_t *written);

#ifdef __cplusplus
}
#endif

#endif

# SPDX-License-Identifier: MPL-2.0
"""Small ctypes binding for the experimental Open Crate sealed-byte C ABI.

Set OPENCRATE_FFI_LIB to the built shared library or pass its path explicitly.
Recipient.close() clears this wrapper's secret buffer; callers own any copies.
"""

from __future__ import annotations

import ctypes as c
import os
from pathlib import Path


class OpenCrateError(Exception):
    def __init__(self, status: int):
        self.status = status
        super().__init__(f"Open Crate native status {status}")


class Recipient:
    def __init__(self, secret: c.Array[c.c_ubyte], public: bytes):
        self._secret = secret
        self.public = public
        self._closed = False

    def close(self) -> None:
        if not self._closed:
            c.memset(self._secret, 0, 32)
            self._closed = True

    def export_secret(self) -> bytes:
        """Return a new secret copy for protected storage; Python cannot wipe it."""
        if self._closed:
            raise ValueError("recipient is closed")
        return bytes(self._secret)

    def __enter__(self) -> "Recipient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def _input(data: bytes) -> tuple[object | None, int]:
    if not data:
        return None, 0
    return c.create_string_buffer(data, len(data)), len(data)


class OpenCrateBytes:
    def __init__(self, library_path: str | os.PathLike[str] | None = None):
        path = library_path or os.environ["OPENCRATE_FFI_LIB"]
        self._lib = c.CDLL(str(Path(path).resolve()))
        self._lib.ocb_abi_version.argtypes = []
        self._lib.ocb_abi_version.restype = c.c_uint32
        if self._lib.ocb_abi_version() != 1:
            raise RuntimeError("Unsupported Open Crate FFI ABI")
        self._lib.ocb_generate_recipient.argtypes = [c.c_void_p, c.c_void_p]
        self._lib.ocb_generate_recipient.restype = c.c_int32
        self._lib.ocb_public_from_secret.argtypes = [c.c_void_p, c.c_void_p]
        self._lib.ocb_public_from_secret.restype = c.c_int32
        signature = [c.c_void_p, c.c_void_p, c.c_size_t, c.c_void_p, c.c_size_t,
                     c.c_void_p, c.c_size_t, c.c_void_p, c.c_size_t, c.POINTER(c.c_size_t)]
        for name in ("ocb_seal", "ocb_open"):
            function = getattr(self._lib, name)
            function.argtypes = signature
            function.restype = c.c_int32

    def generate_recipient(self) -> Recipient:
        secret = (c.c_ubyte * 32)()
        public = (c.c_ubyte * 32)()
        result = self._lib.ocb_generate_recipient(secret, public)
        if result:
            c.memset(secret, 0, 32)
            raise OpenCrateError(result)
        return Recipient(secret, bytes(public))

    def recipient_from_secret(self, secret_bytes: bytes) -> Recipient:
        if len(secret_bytes) != 32:
            raise ValueError("secret key must be 32 bytes")
        secret = (c.c_ubyte * 32).from_buffer_copy(secret_bytes)
        public = (c.c_ubyte * 32)()
        result = self._lib.ocb_public_from_secret(secret, public)
        if result:
            c.memset(secret, 0, 32)
            raise OpenCrateError(result)
        return Recipient(secret, bytes(public))

    def seal(self, public: bytes, purpose: str, context: bytes, plaintext: bytes) -> bytes:
        if len(public) != 32:
            raise ValueError("public key must be 32 bytes")
        return self._operate("ocb_seal", public, purpose, context, plaintext)

    def open(self, recipient: Recipient, purpose: str, context: bytes, envelope: bytes) -> bytes:
        if recipient._closed:
            raise ValueError("recipient is closed")
        return self._operate("ocb_open", recipient._secret, purpose, context, envelope)

    def _operate(self, name: str, key: object, purpose: str,
                 context: bytes, data: bytes) -> bytes:
        function = getattr(self._lib, name)
        purpose_buf, purpose_len = _input(purpose.encode("utf-8"))
        context_buf, context_len = _input(context)
        data_buf, data_len = _input(data)
        key_buf = key if not isinstance(key, bytes) else c.create_string_buffer(key, 32)
        required = c.c_size_t()
        code = function(key_buf, purpose_buf, purpose_len, context_buf, context_len,
                        data_buf, data_len, None, 0, c.byref(required))
        if code == 0 and required.value == 0:
            return b""
        if code != 2:
            raise OpenCrateError(code)
        output = c.create_string_buffer(max(required.value, 1))
        written = c.c_size_t()
        code = function(key_buf, purpose_buf, purpose_len, context_buf, context_len,
                        data_buf, data_len, output, len(output), c.byref(written))
        if code:
            c.memset(output, 0, len(output))
            raise OpenCrateError(code)
        result = output.raw[:written.value]
        c.memset(output, 0, len(output))
        return result

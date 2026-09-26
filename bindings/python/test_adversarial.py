# SPDX-License-Identifier: MPL-2.0
"""Adversarial ABI checks using valid, caller-owned ctypes buffers."""

import ctypes as c
import unittest

from opencrate_bytes import OpenCrateBytes


class AbiTests(unittest.TestCase):
    def setUp(self):
        self.api = OpenCrateBytes()
        self.recipient = self.api.generate_recipient()
        self.addCleanup(self.recipient.close)
        self.purpose = b"test.ffi.v1"
        self.context = b"tenant:object"
        self.plaintext = b"private text"
        self.envelope = self.api.seal(
            self.recipient.public, self.purpose.decode(), self.context, self.plaintext
        )

    def open_raw(self, envelope, purpose=None, context=None, capacity=None):
        purpose = self.purpose if purpose is None else purpose
        context = self.context if context is None else context
        capacity = len(self.plaintext) if capacity is None else capacity
        envelope_buf = c.create_string_buffer(envelope)
        purpose_buf = c.create_string_buffer(purpose)
        context_buf = c.create_string_buffer(context)
        output = (c.c_ubyte * max(capacity, 1))(*([0xa5] * max(capacity, 1)))
        written = c.c_size_t(999)
        code = self.api._lib.ocb_open(
            self.recipient._secret, purpose_buf, len(purpose), context_buf, len(context),
            envelope_buf, len(envelope), output, capacity, c.byref(written)
        )
        return code, written.value, bytes(output)

    def test_positive_control(self):
        code, written, output = self.open_raw(self.envelope)
        self.assertEqual((code, written, output), (0, len(self.plaintext), self.plaintext))

    def test_each_envelope_byte_rejects_damage_without_writing_plaintext(self):
        for index in range(len(self.envelope)):
            damaged = bytearray(self.envelope)
            damaged[index] ^= 1
            code, written, output = self.open_raw(bytes(damaged))
            self.assertIn(code, (5, 7))
            self.assertEqual(written, 0)
            self.assertEqual(output, b"\xa5" * len(self.plaintext))

    def test_wrong_binding_leaves_output_untouched(self):
        for purpose, context in [(b"other.ffi.v1", self.context), (self.purpose, b"other")]:
            code, written, output = self.open_raw(self.envelope, purpose, context)
            self.assertEqual((code, written), (7, 0))
            self.assertEqual(output, b"\xa5" * len(self.plaintext))

    def test_short_output_is_an_allocation_hint_without_authentication(self):
        damaged = bytearray(self.envelope)
        damaged[-1] ^= 1
        code, written, output = self.open_raw(bytes(damaged), capacity=1)
        self.assertEqual((code, written, output), (2, len(self.plaintext), b"\xa5"))
        self.assertEqual(self.open_raw(bytes(damaged))[0], 7)

    def test_empty_and_overlong_purposes_reject_before_output(self):
        for purpose in [b"", b"x" * 129]:
            code, written, output = self.open_raw(self.envelope, purpose=purpose)
            self.assertEqual((code, written), (3, 0))
            self.assertEqual(output, b"\xa5" * len(self.plaintext))

    def test_null_required_pointers_are_rejected(self):
        self.assertEqual(self.api._lib.ocb_generate_recipient(None, None), 1)
        self.assertEqual(self.api._lib.ocb_public_from_secret(None, None), 1)
        self.assertEqual(self.api._lib.ocb_open(None, None, 0, None, 0, None, 0,
                                             None, 0, None), 1)

    def test_seal_allows_input_output_aliasing_after_copy(self):
        capacity = len(self.plaintext) + 77
        buffer = c.create_string_buffer(capacity)
        c.memmove(buffer, self.plaintext, len(self.plaintext))
        public = c.create_string_buffer(self.recipient.public)
        purpose = c.create_string_buffer(self.purpose)
        context = c.create_string_buffer(self.context)
        written = c.c_size_t()
        code = self.api._lib.ocb_seal(public, purpose, len(self.purpose), context,
                                    len(self.context), buffer, len(self.plaintext),
                                    buffer, capacity, c.byref(written))
        self.assertEqual((code, written.value), (0, capacity))
        self.assertEqual(self.api.open(self.recipient, self.purpose.decode(), self.context,
                                      buffer.raw[:written.value]), self.plaintext)

    def test_closed_recipient_is_wiped_and_refused(self):
        self.recipient.close()
        self.assertEqual(bytes(self.recipient._secret), b"\0" * 32)
        with self.assertRaises(ValueError):
            self.api.open(self.recipient, self.purpose.decode(), self.context, self.envelope)


if __name__ == "__main__":
    unittest.main()

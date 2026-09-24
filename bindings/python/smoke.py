"""Run with OPENCRATE_FFI_LIB pointing to the built shared library."""

import ctypes as c

from opencrate_bytes import OpenCrateBytes, OpenCrateError

api = OpenCrateBytes()
with api.generate_recipient() as recipient:
    plaintext = b"arbitrary bytes from Python\x00"
    envelope = api.seal(recipient.public, "example.python.v1", b"object-7", plaintext)
    assert api.open(recipient, "example.python.v1", b"object-7", envelope) == plaintext
    with api.recipient_from_secret(recipient.export_secret()) as restored:
        assert restored.public == recipient.public
        assert api.open(restored, "example.python.v1", b"object-7", envelope) == plaintext
    empty = api.seal(recipient.public, "example.python.v1", b"object-7", b"")
    assert api.open(recipient, "example.python.v1", b"object-7", empty) == b""
    output = c.create_string_buffer(b"stay")
    required = c.c_size_t()
    status = api._lib.ocb_seal(
        c.create_string_buffer(recipient.public, 32),
        c.create_string_buffer(b"example.python.v1"), len(b"example.python.v1"),
        None, 0, c.create_string_buffer(b"input"), 5,
        output, 4, c.byref(required),
    )
    assert status == 2 and required.value == 5 + 77 and output.raw[:4] == b"stay"
    try:
        api.open(recipient, "example.python.v1", b"object-8", envelope)
    except OpenCrateError as error:
        assert error.status == 7
    else:
        raise AssertionError("changed context was accepted")
    try:
        api.open(recipient, "example.python.v1", b"object-7", envelope[:-1] + bytes([envelope[-1] ^ 1]))
    except OpenCrateError as error:
        assert error.status == 7
    else:
        raise AssertionError("damaged envelope was accepted")
print("Python round trip and context rejection passed")

from __future__ import annotations

import struct
from typing import Tuple


_MAGIC = b"RWAPAY1\x00"
_HEADER = struct.Struct(">8sII")


def pack_credential_payload(proof_bytes: bytes, attachment: bytes = b"") -> bytes:
    return _HEADER.pack(_MAGIC, len(proof_bytes), len(attachment)) + proof_bytes + attachment


def unpack_credential_payload(payload: bytes) -> Tuple[bytes, bytes]:
    if len(payload) < _HEADER.size:
        return payload, b""

    magic, proof_len, attachment_len = _HEADER.unpack_from(payload, 0)
    if magic != _MAGIC:
        return payload, b""

    expected = _HEADER.size + proof_len + attachment_len
    if len(payload) != expected:
        return payload, b""

    proof_start = _HEADER.size
    proof_end = proof_start + proof_len
    return payload[proof_start:proof_end], payload[proof_end:]

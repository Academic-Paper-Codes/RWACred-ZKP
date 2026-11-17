from __future__ import annotations

from typing import Any, Tuple

from rwacred.groupsign_bbs04 import GroupSignBBS04


def build_group_sign_backend(
    backend: str,
    pairing: object,
    seed_material: bytes,
) -> Tuple[Any, Any, Any]:
    normalized = backend.strip().lower()
    if normalized == "bbs04":
        return GroupSignBBS04.setup(pairing=pairing, seed_material=seed_material)
    raise ValueError("mock group signature backend has been removed; use group_signature_backend='bbs04'")

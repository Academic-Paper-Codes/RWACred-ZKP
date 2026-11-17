from __future__ import annotations

from dataclasses import dataclass
import hashlib
import importlib.util
from pathlib import Path
import random
import sys
from typing import Any, Literal, Optional


GroupName = Literal["G", "GT"]

try:
    from pypbc import Element, G1, Pairing, Parameters

    PYPBC_AVAILABLE = True
except Exception:
    Element = None  # type: ignore[assignment]
    G1 = None  # type: ignore[assignment]
    Pairing = None  # type: ignore[assignment]
    Parameters = None  # type: ignore[assignment]
    PYPBC_AVAILABLE = False


def _try_load_local_pypbc() -> bool:
    repo_root = Path(__file__).resolve().parents[1]
    candidates = sorted(
        repo_root.glob("third_party/build/pypbc-master/build/lib.*/pypbc*.so")
    )
    for candidate in candidates:
        spec = importlib.util.spec_from_file_location("pypbc", candidate)
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception:
            continue

        sys.modules.setdefault("pypbc", module)

        global Element, G1, Pairing, Parameters, PYPBC_AVAILABLE
        Element = getattr(module, "Element", None)
        G1 = getattr(module, "G1", None)
        Pairing = getattr(module, "Pairing", None)
        Parameters = getattr(module, "Parameters", None)
        PYPBC_AVAILABLE = all(value is not None for value in (Element, G1, Pairing, Parameters))
        if PYPBC_AVAILABLE:
            return True
    return False


if not PYPBC_AVAILABLE:
    _try_load_local_pypbc()


def mod_inverse(value: int, modulus: int) -> int:
    if value % modulus == 0:
        raise ValueError("value has no modular inverse")
    return pow(value, -1, modulus)


def hash_expand(seed: bytes, out_len: int) -> bytes:
    if out_len < 0:
        raise ValueError("out_len must be non-negative")
    if out_len == 0:
        return b""

    out = bytearray()
    counter = 0
    while len(out) < out_len:
        block = hashlib.sha256(counter.to_bytes(4, "big") + seed).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:out_len])


def xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("xor inputs must have same length")
    return bytes(a ^ b for a, b in zip(left, right))


@dataclass(frozen=True)
class GroupElement:
    group: GroupName
    exp: int
    order: int
    backend: str = "pypbc"
    raw: Optional[Any] = None

    def __post_init__(self) -> None:
        if self.group not in ("G", "GT"):
            raise ValueError(f"unsupported group: {self.group}")
        if self.backend != "pypbc":
            raise ValueError(f"unsupported backend: {self.backend}")
        if self.raw is None:
            raise ValueError("pypbc group element must carry raw backend object")
        object.__setattr__(self, "exp", self.exp % self.order)

    def __mul__(self, other: "GroupElement") -> "GroupElement":
        if self.group != other.group or self.order != other.order:
            raise ValueError("group mismatch")
        raw = self.raw * other.raw
        return GroupElement(
            self.group,
            self.exp + other.exp,
            self.order,
            backend="pypbc",
            raw=raw,
        )

    def __truediv__(self, other: "GroupElement") -> "GroupElement":
        return self * other.inv()

    def pow(self, scalar: int) -> "GroupElement":
        raw = self.raw ** int(scalar)
        return GroupElement(
            self.group,
            self.exp * (scalar % self.order),
            self.order,
            backend="pypbc",
            raw=raw,
        )

    def inv(self) -> "GroupElement":
        raw = self.raw ** int(self.order - 1)
        return GroupElement(
            self.group,
            -self.exp,
            self.order,
            backend="pypbc",
            raw=raw,
        )

    def to_bytes(self) -> bytes:
        try:
            if hasattr(self.raw, "to_bytes"):
                return self.raw.to_bytes()
            return bytes(self.raw)
        except Exception:
            return str(self.raw).encode("utf-8")

    def short(self) -> str:
        return f"{self.group}^{self.exp}"


class PBCPairingContext:
    """
    pypbc-backed bilinear context (Type A parameters).

    Notes:
      - We keep algebraic exponents for deterministic debugging/serialization.
      - Real group operations are executed by pypbc in `raw`.
    """

    DEFAULT_TYPE_A_PARAMS = """type a
q 87807107996633125224377819847540498158068831994142082\
1102865339926647563088022295707862517942266222142315585\
8769582317459277713367317481324925129998224791
h 12016012264891146079388821366740534204802954401251311\
822919615131047207289359704531102844802183906537786776
r 730750818665451621361119245571504901405976559617
exp2 159
exp1 107
sign1 1
sign0 1
"""
    DEFAULT_ORDER = 730750818665451621361119245571504901405976559617

    def __init__(self, seed: int, param_string: str | None = None, order: int | None = None) -> None:
        if not PYPBC_AVAILABLE:
            raise ImportError("pypbc is not installed")

        self.order = order or self.DEFAULT_ORDER
        self.rng = random.Random(seed)

        params = Parameters(param_string or self.DEFAULT_TYPE_A_PARAMS)
        self._pairing = Pairing(params)

        self._g_raw = self._deterministic_g(seed)
        gt_raw = self._pairing.apply(self._g_raw, self._g_raw)

        self.g = GroupElement("G", 1, self.order, backend="pypbc", raw=self._g_raw)
        self.gt = GroupElement("GT", 1, self.order, backend="pypbc", raw=gt_raw)

    def _deterministic_g(self, seed: int) -> Any:
        # Preferred path: map seed bytes to G1 deterministically.
        seed_bytes = hashlib.sha256(f"rwacred-g:{seed}".encode("utf-8")).digest()
        if hasattr(Element, "from_hash"):
            try:
                return Element.from_hash(self._pairing, G1, seed_bytes)
            except Exception:
                pass
        return Element.random(self._pairing, G1)

    def random_scalar(self, non_zero: bool = True) -> int:
        if non_zero:
            return self.rng.randrange(1, self.order)
        return self.rng.randrange(0, self.order)

    def identity(self, group: GroupName) -> GroupElement:
        if group == "G":
            return self.g.pow(0)
        return self.gt.pow(0)

    def g_pow(self, scalar: int) -> GroupElement:
        raw = self._g_raw ** int(scalar)
        return GroupElement("G", scalar, self.order, backend="pypbc", raw=raw)

    def gt_pow(self, scalar: int) -> GroupElement:
        raw = self.gt.raw ** int(scalar)
        return GroupElement("GT", scalar, self.order, backend="pypbc", raw=raw)

    def pair(self, left: GroupElement, right: GroupElement) -> GroupElement:
        if left.group != "G" or right.group != "G":
            raise ValueError("pairing only accepts G x G")
        if left.backend != "pypbc" or right.backend != "pypbc":
            raise ValueError("pairing backend mismatch")
        raw = self._pairing.apply(left.raw, right.raw)
        return GroupElement("GT", left.exp * right.exp, self.order, backend="pypbc", raw=raw)


def is_pypbc_available() -> bool:
    return PYPBC_AVAILABLE


def build_pairing_context(
    backend: str | None,
    seed: int,
    order: int | None = None,
    pbc_param_string: str | None = None,
) -> PBCPairingContext:
    normalized = (backend or "pypbc").strip().lower()
    if normalized != "pypbc":
        raise ValueError("mock pairing backend has been removed; use pairing_backend='pypbc'")
    return PBCPairingContext(seed=seed, param_string=pbc_param_string, order=order)

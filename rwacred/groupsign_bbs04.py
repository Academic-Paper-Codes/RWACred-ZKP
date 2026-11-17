from __future__ import annotations

from dataclasses import dataclass
import hashlib
import random
from typing import Dict, Optional

from rwacred.pairing_backend import GroupElement, mod_inverse


def _hash_to_scalar(order: int, payload: bytes, elements: list[GroupElement]) -> int:
    h = hashlib.sha256()
    h.update(len(payload).to_bytes(4, "big"))
    h.update(payload)
    for elem in elements:
        b = elem.to_bytes()
        h.update(len(b).to_bytes(4, "big"))
        h.update(b)
    return int.from_bytes(h.digest(), "big") % order


def _elem_fingerprint(elem: GroupElement) -> str:
    return hashlib.sha256(elem.to_bytes()).hexdigest()


@dataclass(frozen=True)
class BBS04PublicKey:
    g1: GroupElement
    g2: GroupElement
    h: GroupElement
    u: GroupElement
    v: GroupElement
    w: GroupElement


@dataclass(frozen=True)
class BBS04ManagerSecretKey:
    xi1: int
    xi2: int
    gamma: int


@dataclass(frozen=True)
class BBS04MemberSecretKey:
    uid: int
    x: int
    a: GroupElement


@dataclass(frozen=True)
class BBS04Signature:
    t1: GroupElement
    t2: GroupElement
    t3: GroupElement
    c: int
    s_alpha: int
    s_beta: int
    s_x: int
    s_delta1: int
    s_delta2: int


class GroupSignBBS04:
    """
    Real BBS04 group-signature flow over the configured bilinear group.
    """

    def __init__(
        self,
        pairing: object,
        gpk: BBS04PublicKey,
        msk: BBS04ManagerSecretKey,
        rng_seed: int,
    ) -> None:
        self.pairing = pairing
        self.gpk = gpk
        self.msk = msk
        self.order = int(pairing.order)
        self.rng = random.Random(rng_seed)
        self.members: Dict[int, BBS04MemberSecretKey] = {}
        self.open_index: Dict[str, int] = {}

    @classmethod
    def setup(
        cls,
        pairing: object,
        seed_material: bytes,
    ) -> tuple[BBS04ManagerSecretKey, BBS04PublicKey, "GroupSignBBS04"]:
        order = int(pairing.order)
        seed = int.from_bytes(hashlib.sha256(b"bbs04-setup:" + seed_material).digest(), "big")
        rng = random.Random(seed)

        def _rand_nonzero() -> int:
            return rng.randrange(1, order)

        xi1 = _rand_nonzero()
        xi2 = _rand_nonzero()
        gamma = _rand_nonzero()
        g2_exp = _rand_nonzero()
        h_exp = _rand_nonzero()

        g1 = pairing.g
        g2 = pairing.g_pow(g2_exp)
        h = pairing.g_pow(h_exp)
        u = h.pow(mod_inverse(xi1, order))
        v = h.pow(mod_inverse(xi2, order))
        w = g2.pow(gamma)

        gpk = BBS04PublicKey(g1=g1, g2=g2, h=h, u=u, v=v, w=w)
        msk = BBS04ManagerSecretKey(xi1=xi1, xi2=xi2, gamma=gamma)
        engine = cls(pairing=pairing, gpk=gpk, msk=msk, rng_seed=seed ^ 0xB504)
        return msk, gpk, engine

    def keygen(self, uid: int) -> BBS04MemberSecretKey:
        while True:
            x = self.rng.randrange(1, self.order)
            denom = (self.msk.gamma + x) % self.order
            if denom != 0:
                break

        a = self.gpk.g1.pow(mod_inverse(denom, self.order))
        member = BBS04MemberSecretKey(uid=uid, x=x, a=a)
        self.members[uid] = member
        self.open_index[_elem_fingerprint(a)] = uid
        return member

    def sign(self, member_key: BBS04MemberSecretKey, signer_uid: int, payload: bytes) -> BBS04Signature:
        if member_key.uid != signer_uid:
            raise ValueError("member key uid mismatch")
        if signer_uid not in self.members:
            raise ValueError("member is not registered in group-sign engine")

        alpha = self.rng.randrange(0, self.order)
        beta = self.rng.randrange(0, self.order)
        delta1 = (member_key.x * alpha) % self.order
        delta2 = (member_key.x * beta) % self.order

        t1 = self.gpk.u.pow(alpha)
        t2 = self.gpk.v.pow(beta)
        t3 = member_key.a * self.gpk.h.pow((alpha + beta) % self.order)

        r_alpha = self.rng.randrange(0, self.order)
        r_beta = self.rng.randrange(0, self.order)
        r_x = self.rng.randrange(0, self.order)
        r_delta1 = self.rng.randrange(0, self.order)
        r_delta2 = self.rng.randrange(0, self.order)

        r1 = self.gpk.u.pow(r_alpha)
        r2 = self.gpk.v.pow(r_beta)

        e_t3_g2 = self.pairing.pair(t3, self.gpk.g2)
        e_h_w = self.pairing.pair(self.gpk.h, self.gpk.w)
        e_h_g2 = self.pairing.pair(self.gpk.h, self.gpk.g2)

        r3 = (
            e_t3_g2.pow(r_x)
            * e_h_w.pow((-r_alpha - r_beta) % self.order)
            * e_h_g2.pow((-r_delta1 - r_delta2) % self.order)
        )
        r4 = t1.pow(r_x) * self.gpk.u.pow((-r_delta1) % self.order)
        r5 = t2.pow(r_x) * self.gpk.v.pow((-r_delta2) % self.order)

        c = _hash_to_scalar(self.order, payload, [t1, t2, t3, r1, r2, r3, r4, r5])

        s_alpha = (r_alpha + c * alpha) % self.order
        s_beta = (r_beta + c * beta) % self.order
        s_x = (r_x + c * member_key.x) % self.order
        s_delta1 = (r_delta1 + c * delta1) % self.order
        s_delta2 = (r_delta2 + c * delta2) % self.order

        return BBS04Signature(
            t1=t1,
            t2=t2,
            t3=t3,
            c=c,
            s_alpha=s_alpha,
            s_beta=s_beta,
            s_x=s_x,
            s_delta1=s_delta1,
            s_delta2=s_delta2,
        )

    def verify(self, pk_rwa: BBS04PublicKey, payload: bytes, signature: BBS04Signature) -> bool:
        gpk = pk_rwa if isinstance(pk_rwa, BBS04PublicKey) else self.gpk
        c = signature.c % self.order

        r1 = gpk.u.pow(signature.s_alpha) * signature.t1.pow((-c) % self.order)
        r2 = gpk.v.pow(signature.s_beta) * signature.t2.pow((-c) % self.order)

        e_t3_g2 = self.pairing.pair(signature.t3, gpk.g2)
        e_h_w = self.pairing.pair(gpk.h, gpk.w)
        e_h_g2 = self.pairing.pair(gpk.h, gpk.g2)
        ratio = self.pairing.pair(gpk.g1, gpk.g2) / self.pairing.pair(signature.t3, gpk.w)

        r3 = (
            e_t3_g2.pow(signature.s_x)
            * e_h_w.pow((-signature.s_alpha - signature.s_beta) % self.order)
            * e_h_g2.pow((-signature.s_delta1 - signature.s_delta2) % self.order)
            * ratio.pow((-c) % self.order)
        )
        r4 = signature.t1.pow(signature.s_x) * gpk.u.pow((-signature.s_delta1) % self.order)
        r5 = signature.t2.pow(signature.s_x) * gpk.v.pow((-signature.s_delta2) % self.order)

        c_prime = _hash_to_scalar(
            self.order,
            payload,
            [signature.t1, signature.t2, signature.t3, r1, r2, r3, r4, r5],
        )
        return c_prime == c

    def reveal(
        self,
        sk_rwa: BBS04ManagerSecretKey,
        payload: bytes,
        signature: BBS04Signature,
    ) -> Optional[int]:
        if not isinstance(sk_rwa, BBS04ManagerSecretKey):
            return None
        if not self.verify(self.gpk, payload, signature):
            return None

        a = signature.t3 / (signature.t1.pow(sk_rwa.xi1) * signature.t2.pow(sk_rwa.xi2))
        return self.open_index.get(_elem_fingerprint(a))

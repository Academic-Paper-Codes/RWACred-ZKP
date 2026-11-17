from __future__ import annotations

from dataclasses import dataclass, field
from math import ceil
import json
from typing import Dict, List, Optional, Set, Tuple, Any

from rwacred.credential_payload import unpack_credential_payload
from rwacred.groupsign_backend import build_group_sign_backend
from rwacred.pairing_backend import (
    GroupElement,
    build_pairing_context,
    hash_expand,
    mod_inverse,
    xor_bytes,
)
from rwacred.zk_backends import ZKBackend, build_zk_backend


def _block_index(uid: int, n: int) -> int:
    return ceil(uid / n)


def _slot_index(uid: int, n: int) -> int:
    # Consistent with Register's block range [kn-n+1, ..., kn].
    return ((uid - 1) % n) + 1


@dataclass
class SchemeConfig:
    security_lambda: int = 128
    max_users: int = 8
    users_per_block: int = 4
    rng_seed: int = 20260204
    pairing_backend: str = "pypbc"
    pairing_order: Optional[int] = None
    pbc_param_string: Optional[str] = None
    group_signature_backend: str = "bbs04"
    zk_backend: str = "groth16_snarkjs"
    snarkjs_cmd: str = "scripts/snarkjs_local.sh"
    groth16_wasm_path: Optional[str] = None
    groth16_zkey_path: Optional[str] = None
    groth16_vkey_path: Optional[str] = None
    groth16_input_template: Optional[str] = None

    @property
    def block_count(self) -> int:
        return ceil(self.max_users / self.users_per_block)


@dataclass
class UserSecretMaterial:
    uid: int
    uid_prime: int
    sk_id: int
    pk_id: GroupElement
    pap_id: Dict[int, GroupElement]
    sk_rwa_id: Optional[Any] = None


@dataclass
class Ciphertext:
    policy: List[int]
    c1: List[GroupElement]
    c2: List[GroupElement]
    c3: GroupElement
    c4: List[GroupElement]
    c5: bytes
    signature: Any
    debug: Dict[str, int] = field(default_factory=dict)


@dataclass
class VerifyResult:
    signature_ok: bool
    authorized: bool
    proof_ok: bool
    recovered_proof: Optional[bytes]
    shared_secret: Optional[GroupElement]

    @property
    def success(self) -> bool:
        return self.signature_ok and self.authorized and self.proof_ok


class RWACredScheme:
    def __init__(self, config: SchemeConfig) -> None:
        self.config = config
        self.pairing = build_pairing_context(
            backend=config.pairing_backend,
            seed=config.rng_seed,
            order=config.pairing_order,
            pbc_param_string=config.pbc_param_string,
        )

        self.zk_backend: ZKBackend = build_zk_backend(
            backend=config.zk_backend,
            snarkjs_cmd=config.snarkjs_cmd,
            groth16_wasm_path=config.groth16_wasm_path,
            groth16_zkey_path=config.groth16_zkey_path,
            groth16_vkey_path=config.groth16_vkey_path,
            groth16_input_template=config.groth16_input_template,
        )

        self.z: Optional[int] = None
        self.h: Dict[int, GroupElement] = {}
        self.pp: Dict[int, GroupElement] = {}

        # aux from the paper:
        #   - as set form L_i = { ... } (for exact update semantics in Register),
        #   - and as current aggregate (for direct Update lookup during Verify).
        self.aux_sets: Dict[int, Set[GroupElement]] = {}
        self.aux_current: Dict[int, GroupElement] = {}
        self.aux_history: Dict[Tuple[int, str], GroupElement] = {}

        self.users: Dict[int, UserSecretMaterial] = {}
        self.block_members: Dict[int, List[int]] = {}

        self.sk_rwa: Optional[Any] = None
        self.pk_rwa: Optional[Any] = None
        self.group_sign: Optional[Any] = None

    # ----------------------------
    # Paper algorithm: SysSetup
    # ----------------------------
    def sys_setup(self) -> None:
        n = self.config.users_per_block
        b = self.config.block_count
        n_max = self.config.max_users

        self.z = self.pairing.random_scalar(non_zero=True)
        self.h = {}
        for i in range(1, 2 * n + 1):
            if i == n + 1:
                continue
            zi = pow(self.z, i, self.pairing.order)
            self.h[i] = self.pairing.g_pow(zi)

        self.pp = {k: self.pairing.identity("G") for k in range(1, b + 1)}

        self.aux_sets = {uid: {self.pairing.identity("G")} for uid in range(1, n_max + 1)}
        self.aux_current = {uid: self.pairing.identity("G") for uid in range(1, n_max + 1)}
        self.aux_history = {}
        self.block_members = {k: [] for k in range(1, b + 1)}

    # ----------------------------
    # Paper algorithm: RWASetup
    # ----------------------------
    def rwa_setup(self) -> None:
        seed_material = self.pairing.random_scalar(non_zero=True).to_bytes(32, "big")
        sk_rwa, pk_rwa, engine = build_group_sign_backend(
            backend=self.config.group_signature_backend,
            pairing=self.pairing,
            seed_material=seed_material,
        )
        self.sk_rwa = sk_rwa
        self.pk_rwa = pk_rwa
        self.group_sign = engine

    # ----------------------------
    # Paper algorithm: KeyGen
    # ----------------------------
    def keygen(self, uid: int, x_override: Optional[int] = None) -> UserSecretMaterial:
        self._require_setup()

        if uid < 1 or uid > self.config.max_users:
            raise ValueError(f"uid out of range: {uid}")

        n = self.config.users_per_block
        uid_prime = _slot_index(uid, n)

        x_id = x_override % self.pairing.order if x_override is not None else self.pairing.random_scalar(non_zero=True)
        if x_id == 0:
            raise ValueError("x_id must be non-zero")

        pk_id = self.h[uid_prime].pow(x_id)

        pap_id: Dict[int, GroupElement] = {}
        for slot in range(1, n + 1):
            if slot == uid_prime:
                continue  # phi in the paper
            h_index = n + uid_prime - slot + 1
            pap_id[slot] = self.h[h_index].pow(x_id)

        user = UserSecretMaterial(
            uid=uid,
            uid_prime=uid_prime,
            sk_id=x_id,
            pk_id=pk_id,
            pap_id=pap_id,
        )
        self.users[uid] = user
        return user

    # ----------------------------
    # Paper algorithm: Register
    # ----------------------------
    def register(self, user: UserSecretMaterial) -> Any:
        self._require_setup()
        if self.group_sign is None:
            raise ValueError("RWASetup must run first")

        self._check_register_equations(user)

        n = self.config.users_per_block
        k = _block_index(user.uid, n)

        self.pp[k] = self.pp[k] * user.pk_id
        self.block_members[k].append(user.uid)

        block_start = (k - 1) * n + 1
        block_end = min(k * n, self.config.max_users)

        # L_i' = L_i U {L_i * pap_i}
        for target_uid in range(block_start, block_end + 1):
            if target_uid == user.uid:
                continue
            slot = _slot_index(target_uid, n)
            pap_component = user.pap_id[slot]

            old_set = self.aux_sets[target_uid]
            new_candidates = {item * pap_component for item in old_set}
            self.aux_sets[target_uid] = old_set | new_candidates

            # Current aggregate used by Update/Verify path.
            self.aux_current[target_uid] = self.aux_current[target_uid] * pap_component

        # Snapshot current C_(k) -> corresponding L for each user in this block.
        c_key = self._element_key(self.pp[k])
        for target_uid in range(block_start, block_end + 1):
            self.aux_history[(target_uid, c_key)] = self.aux_current[target_uid]

        sk_rwa_id = self.group_sign.keygen(user.uid)
        self.users[user.uid].sk_rwa_id = sk_rwa_id
        return sk_rwa_id

    # ----------------------------
    # Paper algorithm: CredGen
    # ----------------------------
    def credgen(
        self,
        owner_uid: int,
        policy: List[int],
        proof_payload: bytes,
        r_override: Optional[int] = None,
        s_override: Optional[int] = None,
        keep_debug: bool = True,
    ) -> Ciphertext:
        self._require_setup()
        if self.group_sign is None:
            raise ValueError("RWASetup must run first")

        owner = self.users.get(owner_uid)
        if owner is None or owner.sk_rwa_id is None:
            raise ValueError("owner must finish KeyGen + Register first")

        for uid in policy:
            if uid not in self.users:
                raise ValueError(f"policy user not registered: {uid}")

        r = r_override % self.pairing.order if r_override is not None else self.pairing.random_scalar(non_zero=True)
        s = s_override % self.pairing.order if s_override is not None else self.pairing.random_scalar(non_zero=True)
        if r == 0 or s == 0:
            raise ValueError("r and s must be non-zero")

        shared = self.pairing.gt_pow(s)  # corresponds to e(g,g)^s

        c1: List[GroupElement] = []
        c2: List[GroupElement] = []
        c4: List[GroupElement] = []

        n = self.config.users_per_block
        for uid in policy:
            k_i = _block_index(uid, n)
            uid_prime = _slot_index(uid, n)

            c1_i = self.pp[k_i]
            c2_i = self.pairing.pair(c1_i, self.h[n + 1 - uid_prime]).pow(r)
            c4_i = self.pairing.pair(self.h[uid_prime], self.h[n + 1 - uid_prime]).pow(r) * shared

            c1.append(c1_i)
            c2.append(c2_i)
            c4.append(c4_i)

        c3 = self.pairing.g_pow(r)
        mask = hash_expand(shared.to_bytes(), len(proof_payload))
        c5 = xor_bytes(proof_payload, mask)

        core_bytes = self._serialize_ciphertext_core(policy=policy, c1=c1, c2=c2, c3=c3, c4=c4, c5=c5)
        signature = self.group_sign.sign(owner.sk_rwa_id, owner_uid, core_bytes)

        debug: Dict[str, int] = {}
        if keep_debug:
            debug = {"r": r, "s": s}

        return Ciphertext(
            policy=list(policy),
            c1=c1,
            c2=c2,
            c3=c3,
            c4=c4,
            c5=c5,
            signature=signature,
            debug=debug,
        )

    # ----------------------------
    # Paper algorithm: Update
    # ----------------------------
    def update(self, uid: int, c_k: GroupElement) -> GroupElement:
        self._require_setup()
        c_key = self._element_key(c_k)
        history_key = (uid, c_key)
        if history_key in self.aux_history:
            return self.aux_history[history_key]
        return self.aux_current[uid]

    # ----------------------------
    # Paper algorithm: Verify
    # ----------------------------
    def verify(self, verifier_uid: int, ciphertext: Ciphertext) -> VerifyResult:
        self._require_setup()
        if self.group_sign is None or self.pk_rwa is None:
            raise ValueError("RWASetup must run first")

        core_bytes = self._serialize_ciphertext_core(
            policy=ciphertext.policy,
            c1=ciphertext.c1,
            c2=ciphertext.c2,
            c3=ciphertext.c3,
            c4=ciphertext.c4,
            c5=ciphertext.c5,
        )
        signature_ok = self.group_sign.verify(self.pk_rwa, core_bytes, ciphertext.signature)
        if not signature_ok:
            return VerifyResult(False, False, False, None, None)

        if verifier_uid not in ciphertext.policy:
            return VerifyResult(True, False, False, None, None)

        user = self.users.get(verifier_uid)
        if user is None:
            return VerifyResult(True, False, False, None, None)

        policy_index = ciphertext.policy.index(verifier_uid)
        c1_i = ciphertext.c1[policy_index]
        c2_i = ciphertext.c2[policy_index]
        c4_i = ciphertext.c4[policy_index]

        l_id = self.update(verifier_uid, c1_i)
        inv_sk = mod_inverse(user.sk_id, self.pairing.order)

        # s = c4_i / ((e(L_id, c3)^-1 * c2_i)^(1/sk_id))
        inner = (self.pairing.pair(l_id, ciphertext.c3).inv() * c2_i).pow(inv_sk)
        shared = c4_i / inner

        recovered_proof = xor_bytes(ciphertext.c5, hash_expand(shared.to_bytes(), len(ciphertext.c5)))
        proof_bytes, _ = unpack_credential_payload(recovered_proof)
        proof_ok = self.zk_backend.verify_asset_proof(proof_bytes)

        return VerifyResult(
            signature_ok=True,
            authorized=True,
            proof_ok=proof_ok,
            recovered_proof=recovered_proof,
            shared_secret=shared,
        )

    def reveal_owner(self, ciphertext: Ciphertext) -> Optional[int]:
        if self.group_sign is None or self.sk_rwa is None:
            raise ValueError("RWASetup must run first")
        core_bytes = self._serialize_ciphertext_core(
            policy=ciphertext.policy,
            c1=ciphertext.c1,
            c2=ciphertext.c2,
            c3=ciphertext.c3,
            c4=ciphertext.c4,
            c5=ciphertext.c5,
        )
        return self.group_sign.reveal(self.sk_rwa, core_bytes, ciphertext.signature)

    def conformance_check(self, ciphertext: Ciphertext, verifier_uid: int, verify_result: VerifyResult) -> Dict[str, bool]:
        """
        Equation-level consistency checks against the paper's construction.
        """
        checks: Dict[str, bool] = {}
        n = self.config.users_per_block

        checks["syssetup_h_count"] = len(self.h) == (2 * n - 1)
        checks["syssetup_h_skip_n_plus_1"] = (n + 1) not in self.h

        reg_ok = True
        for user in self.users.values():
            try:
                self._check_register_equations(user)
            except Exception:
                reg_ok = False
                break
        checks["register_pairing_equations"] = reg_ok

        if "r" in ciphertext.debug and "s" in ciphertext.debug:
            r = ciphertext.debug["r"]
            s = ciphertext.debug["s"]
            shared_expected = self.pairing.gt_pow(s)
            credgen_ok = True
            for idx, uid in enumerate(ciphertext.policy):
                k_i = _block_index(uid, n)
                uid_prime = _slot_index(uid, n)

                c1_expected = self.pp[k_i]
                c2_expected = self.pairing.pair(c1_expected, self.h[n + 1 - uid_prime]).pow(r)
                c4_expected = self.pairing.pair(self.h[uid_prime], self.h[n + 1 - uid_prime]).pow(r) * shared_expected

                if ciphertext.c1[idx] != c1_expected:
                    credgen_ok = False
                if ciphertext.c2[idx] != c2_expected:
                    credgen_ok = False
                if ciphertext.c4[idx] != c4_expected:
                    credgen_ok = False
            checks["credgen_equations"] = credgen_ok
        else:
            checks["credgen_equations"] = False

        checks["verify_success"] = verify_result.success
        return checks

    def generate_asset_proof(self, asset_message: Dict[str, Any], threshold: int) -> bytes:
        return self.zk_backend.generate_asset_proof(asset_message=asset_message, threshold=threshold)

    # ----------------------------
    # Internal helpers
    # ----------------------------
    def _check_register_equations(self, user: UserSecretMaterial) -> None:
        if user.uid < 1 or user.uid > self.config.max_users:
            raise ValueError("uid outside [1, N]")

        n = self.config.users_per_block
        left = self.pairing.pair(user.pk_id, self.h[n])

        for slot in range(1, n + 1):
            if slot == user.uid_prime:
                continue
            base = self.pairing.g if slot == 1 else self.h[slot - 1]
            right = self.pairing.pair(user.pap_id[slot], base)
            if right != left:
                raise ValueError(f"register equation failed for uid={user.uid}, slot={slot}")

    def _serialize_ciphertext_core(
        self,
        policy: List[int],
        c1: List[GroupElement],
        c2: List[GroupElement],
        c3: GroupElement,
        c4: List[GroupElement],
        c5: bytes,
    ) -> bytes:
        payload = {
            "policy": policy,
            "c1_exp": [elem.exp for elem in c1],
            "c2_exp": [elem.exp for elem in c2],
            "c3_exp": c3.exp,
            "c4_exp": [elem.exp for elem in c4],
            "c5_hex": c5.hex(),
        }
        return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _element_key(elem: GroupElement) -> str:
        return f"{elem.group}:{elem.exp}"

    def _require_setup(self) -> None:
        if self.z is None or not self.h or not self.pp:
            raise ValueError("SysSetup must run first")

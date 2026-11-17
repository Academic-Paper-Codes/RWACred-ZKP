from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, Any

from rwacred import RWACredScheme, SchemeConfig


def _load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run RWACred end-to-end demo.")
    parser.add_argument(
        "config_path",
        nargs="?",
        help="Path to JSON config file. Overrides --profile if provided.",
    )
    parser.add_argument(
        "--profile",
        choices=("sigfast",),
        default="sigfast",
        help="Use built-in config profile when config_path is not provided.",
    )
    return parser.parse_args()


def _resolve_config_path(args: argparse.Namespace) -> Path:
    if args.config_path:
        return Path(args.config_path)
    return Path(__file__).resolve().with_name("rwacred_config.sig_fast_demo.json")


def main() -> None:
    args = _parse_args()
    cfg_path = _resolve_config_path(args)
    if not cfg_path.exists():
        raise FileNotFoundError(f"missing config file: {cfg_path}")

    cfg_raw = _load_json(cfg_path)

    scheme_cfg = SchemeConfig(
        security_lambda=int(cfg_raw.get("security_lambda", 128)),
        max_users=int(cfg_raw.get("max_users", 8)),
        users_per_block=int(cfg_raw.get("users_per_block", 4)),
        rng_seed=int(cfg_raw.get("rng_seed", 20260204)),
        pairing_backend=str(cfg_raw.get("pairing_backend", "pypbc")),
        pairing_order=cfg_raw.get("pairing_order"),
        pbc_param_string=cfg_raw.get("pbc_param_string"),
        group_signature_backend=str(cfg_raw.get("group_signature_backend", "bbs04")),
        zk_backend=str(cfg_raw.get("zk_backend", "groth16_snarkjs")),
        snarkjs_cmd=str(cfg_raw.get("snarkjs_cmd", "scripts/snarkjs_local.sh")),
        groth16_wasm_path=cfg_raw.get("groth16_wasm_path"),
        groth16_zkey_path=cfg_raw.get("groth16_zkey_path"),
        groth16_vkey_path=cfg_raw.get("groth16_vkey_path"),
        groth16_input_template=cfg_raw.get("groth16_input_template"),
    )

    owner_uid = int(cfg_raw["owner_uid"])
    policy = [int(v) for v in cfg_raw["policy"]]
    non_designated_uid = int(cfg_raw["non_designated_uid"])
    register_user_ids = [int(v) for v in cfg_raw.get("register_user_ids", list(range(1, scheme_cfg.max_users + 1)))]

    x_override_map = {int(k): int(v) for k, v in cfg_raw.get("user_secret_x", {}).items()}
    r_override = int(cfg_raw.get("credgen_randomness", {}).get("r", 0)) or None
    s_override = int(cfg_raw.get("credgen_randomness", {}).get("s", 0)) or None

    asset_message = dict(cfg_raw["asset_message"])
    threshold = int(cfg_raw["valuation_threshold"])

    try:
        scheme = RWACredScheme(scheme_cfg)
    except ImportError as exc:
        raise RuntimeError(
            f"pairing_backend={scheme_cfg.pairing_backend!r} requires pypbc, but import failed: {exc}"
        ) from exc

    scheme.sys_setup()
    scheme.rwa_setup()

    print("[1/7] SysSetup + RWASetup finished")
    print(f"       pairing_backend={scheme_cfg.pairing_backend}")
    print(f"       group_signature_backend={scheme_cfg.group_signature_backend}")
    print(f"       zk_backend={scheme_cfg.zk_backend}")
    print(f"       N={scheme_cfg.max_users}, n={scheme_cfg.users_per_block}, B={scheme_cfg.block_count}")

    for uid in register_user_ids:
        user = scheme.keygen(uid=uid, x_override=x_override_map.get(uid))
        scheme.register(user)
    print(f"[2/7] KeyGen + Register finished for users: {register_user_ids}")

    proof_payload = scheme.generate_asset_proof(asset_message=asset_message, threshold=threshold)
    print(f"[3/7] ZK proof generated, bytes={len(proof_payload)}")

    ciphertext = scheme.credgen(
        owner_uid=owner_uid,
        policy=policy,
        proof_payload=proof_payload,
        r_override=r_override,
        s_override=s_override,
        keep_debug=True,
    )
    print(f"[4/7] CredGen finished by owner uid={owner_uid} for policy={policy}")

    first_result = None
    designated_ok = True
    for uid in policy:
        result = scheme.verify(verifier_uid=uid, ciphertext=ciphertext)
        designated_ok = designated_ok and result.success
        if first_result is None:
            first_result = result
        print(f"[5/7] Verify(uid={uid}) -> {result.success}")

    non_result = scheme.verify(verifier_uid=non_designated_uid, ciphertext=ciphertext)
    print(f"[6/7] Verify(non-designated uid={non_designated_uid}) -> {non_result.success}")

    revealed_owner = scheme.reveal_owner(ciphertext)
    print(f"[7/7] GroupSign.Reveal -> owner uid={revealed_owner}")

    if first_result is None:
        raise RuntimeError("policy is empty; cannot run conformance check")
    checks = scheme.conformance_check(ciphertext=ciphertext, verifier_uid=policy[0], verify_result=first_result)
    print("\nConformance check against paper equations:")
    for key in sorted(checks.keys()):
        print(f"  - {key}: {checks[key]}")
    if not (designated_ok and not non_result.success and revealed_owner == owner_uid and all(checks.values())):
        raise SystemExit("RWACred smoke test failed")


if __name__ == "__main__":
    main()

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any, Dict, Protocol

def _canonical_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


class ZKBackend(Protocol):
    name: str

    def generate_asset_proof(self, asset_message: Dict[str, Any], threshold: int) -> bytes:
        ...

    def verify_asset_proof(self, proof_bytes: bytes) -> bool:
        ...


@dataclass
class SnarkJSGroth16Config:
    snarkjs_cmd: str
    wasm_path: Path
    zkey_path: Path
    vkey_path: Path
    template_input_path: Path


@dataclass
class SnarkJSGroth16Backend:
    """
    Real Groth16 backend powered by snarkjs.

    It assumes you already have a compiled circuit and matching Groth16 artifacts:
      - circuit.wasm
      - circuit_final.zkey
      - verification_key.json
    """

    config: SnarkJSGroth16Config
    name: str = "groth16_snarkjs"

    def _ensure_tooling(self) -> None:
        if shutil.which(self.config.snarkjs_cmd) is None:
            raise RuntimeError(f"missing command: {self.config.snarkjs_cmd}")
        for p in (
            self.config.wasm_path,
            self.config.zkey_path,
            self.config.vkey_path,
            self.config.template_input_path,
        ):
            if not p.exists():
                raise FileNotFoundError(f"missing groth16 artifact: {p}")

    def _build_input(self, asset_message: Dict[str, Any], threshold: int) -> Dict[str, Any]:
        with self.config.template_input_path.open("r", encoding="utf-8") as f:
            template = json.load(f)
        payload = dict(template)

        # Allow the asset message to directly provide circuit inputs
        # (e.g., r/s/msghash/pubkey/valuation/legal_status).
        for key, value in asset_message.items():
            payload[key] = value

        if "d" in payload:
            payload["d"] = int(threshold)
        elif "threshold" in payload:
            payload["threshold"] = int(threshold)
        else:
            payload["d"] = int(threshold)
        return payload

    def generate_asset_proof(self, asset_message: Dict[str, Any], threshold: int) -> bytes:
        self._ensure_tooling()
        input_payload = self._build_input(asset_message=asset_message, threshold=threshold)

        with tempfile.TemporaryDirectory(prefix="rwacred-groth16-") as td:
            work = Path(td)
            input_json = work / "input.json"
            proof_json = work / "proof.json"
            public_json = work / "public.json"

            input_json.write_bytes(_canonical_bytes(input_payload))

            cmd = [
                self.config.snarkjs_cmd,
                "groth16",
                "fullprove",
                str(input_json),
                str(self.config.wasm_path),
                str(self.config.zkey_path),
                str(proof_json),
                str(public_json),
            ]
            proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
            if proc.returncode != 0:
                raise RuntimeError(f"snarkjs fullprove failed: {proc.stderr.strip() or proc.stdout.strip()}")

            proof = json.loads(proof_json.read_text(encoding="utf-8"))
            public_signals = json.loads(public_json.read_text(encoding="utf-8"))

        package = {
            "proof_system": "groth16-snarkjs",
            "proof": proof,
            "public_signals": public_signals,
        }
        return _canonical_bytes(package)

    def verify_asset_proof(self, proof_bytes: bytes) -> bool:
        try:
            package = json.loads(proof_bytes.decode("utf-8"))
        except Exception:
            return False
        if package.get("proof_system") != "groth16-snarkjs":
            return False

        try:
            proof = package["proof"]
            public_signals = package["public_signals"]
        except Exception:
            return False

        try:
            self._ensure_tooling()
        except Exception:
            return False

        with tempfile.TemporaryDirectory(prefix="rwacred-groth16-verify-") as td:
            work = Path(td)
            proof_json = work / "proof.json"
            public_json = work / "public.json"

            proof_json.write_text(json.dumps(proof, ensure_ascii=True), encoding="utf-8")
            public_json.write_text(json.dumps(public_signals, ensure_ascii=True), encoding="utf-8")

            cmd = [
                self.config.snarkjs_cmd,
                "groth16",
                "verify",
                str(self.config.vkey_path),
                str(public_json),
                str(proof_json),
            ]
            proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
            if proc.returncode != 0:
                return False
            out = (proc.stdout + "\n" + proc.stderr).lower()
            return "ok" in out


def build_zk_backend(
    backend: str,
    snarkjs_cmd: str = "snarkjs",
    groth16_wasm_path: str | None = None,
    groth16_zkey_path: str | None = None,
    groth16_vkey_path: str | None = None,
    groth16_input_template: str | None = None,
) -> ZKBackend:
    normalized = backend.strip().lower()
    if normalized == "groth16_snarkjs":
        missing = [
            name
            for name, value in {
                "groth16_wasm_path": groth16_wasm_path,
                "groth16_zkey_path": groth16_zkey_path,
                "groth16_vkey_path": groth16_vkey_path,
                "groth16_input_template": groth16_input_template,
            }.items()
            if not value
        ]
        if missing:
            raise ValueError(f"groth16_snarkjs requires config fields: {', '.join(missing)}")
        return SnarkJSGroth16Backend(
            config=SnarkJSGroth16Config(
                snarkjs_cmd=snarkjs_cmd,
                wasm_path=Path(str(groth16_wasm_path)),
                zkey_path=Path(str(groth16_zkey_path)),
                vkey_path=Path(str(groth16_vkey_path)),
                template_input_path=Path(str(groth16_input_template)),
            )
        )
    raise ValueError("mock zk backend has been removed; use zk_backend='groth16_snarkjs'")

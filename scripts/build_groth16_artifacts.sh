#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
step="${1:-all}"
circuit=rwacred_verify_sig_fast
out=zk_artifacts_sig_fast
snarkjs="$root/scripts/snarkjs_local.sh"
cd "$root"

if [[ "$#" -gt 2 || "${2:-sigfast}" != "sigfast" ]]; then
  echo "Usage: $0 [all|compile|setup|smoke] [sigfast]" >&2
  exit 1
fi

compile() {
  local circom="${CIRCOM_BIN:-circom}"
  command -v "$circom" >/dev/null 2>&1 || {
    echo "Install Circom 2.2.3 or set CIRCOM_BIN." >&2
    exit 1
  }
  [[ -d "$root/node_modules/circomlib/circuits" ]] || {
    echo "Missing circomlib. Run npm ci in $root." >&2
    exit 1
  }
  mkdir -p "$out"
  "$circom" "zk_circuits/$circuit.circom" -l node_modules --r1cs --wasm --sym -o "$out"
  cp "$out/${circuit}_js/$circuit.wasm" "$out/circuit.wasm"
  node scripts/generate_sig_fast_input.js > "$out/input_template.example.json"
}

setup_demo() {
  local ptau="${RWACRED_PTAU:-$out/pot15_demo_final.ptau}"
  if [[ -z "${RWACRED_PTAU:-}" && ! -f "$ptau" ]]; then
    "$snarkjs" powersoftau new bn128 15 "$out/pot15_demo_0000.ptau"
    "$snarkjs" powersoftau prepare phase2 "$out/pot15_demo_0000.ptau" "$ptau"
  fi
  echo "Generating reproduction-only Groth16 parameters." >&2
  "$snarkjs" groth16 setup "$out/$circuit.r1cs" "$ptau" "$out/circuit_0000.zkey"
  "$snarkjs" zkey beacon "$out/circuit_0000.zkey" "$out/circuit_final.zkey" \
    0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 10
  "$snarkjs" zkey export verificationkey "$out/circuit_final.zkey" "$out/verification_key.json"
}

smoke() (
  work="$(mktemp -d)"
  trap 'rm -f "$work/proof.json" "$work/public.json"; rmdir "$work"' EXIT
  "$snarkjs" groth16 fullprove "$out/input_template.example.json" "$out/circuit.wasm" \
    "$out/circuit_final.zkey" "$work/proof.json" "$work/public.json"
  "$snarkjs" groth16 verify "$out/verification_key.json" "$work/public.json" "$work/proof.json"
)

case "$step" in
  all) compile; setup_demo; smoke ;;
  compile) compile ;;
  setup) setup_demo ;;
  smoke) smoke ;;
  *)
    echo "Usage: $0 [all|compile|setup|smoke] [sigfast]" >&2
    exit 1
    ;;
esac

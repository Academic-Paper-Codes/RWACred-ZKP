# RWACred

Source implementation for **RWACred: Secure and Efficient Asset Credentials for Decentralized Real World Assets**, IEEE GLOBECOM 2026.

RWACred lets an asset owner issue one zero-knowledge credential to a set of designated verifiers and lets the platform identify the issuer of a group-signed credential when required. The paper profile, `sigfast`, uses Groth16 to check a BabyJub EdDSA signature over a Poseidon hash of the hidden asset attributes, a valuation threshold, and legal status.

## Run the RWACred demo

The experiment used Python 3.12.5 on Apple Silicon macOS. For the demo, use Node.js 24 (the recorded toolchain used 24.13.0), an Apple command-line toolchain, and the PBC/GMP backend. The macOS installer also requires `curl`, `tar`, `unzip`, `make`, `flex` and `bison`. Build-from-source additionally requires [Circom 2.2.3](https://github.com/iden3/circom/releases/tag/v2.2.3) on `PATH`.

Run these commands from the repository root.

```sh
python3 -m venv .venv
source .venv/bin/activate
npm ci
chmod +x scripts/snarkjs_local.sh
bash scripts/setup_pypbc.sh
bash scripts/build_groth16_artifacts.sh
python run_rwacred_demo.py
```

A successful demo accepts all designated verifiers, rejects the non-designated verifier, reveals the correct owner, and passes each equation check. The circuit build generates all Groth16 artifacts locally.

The sample values and Groth16 setup are for research and testing. The build uses an uncontributed development Powers of Tau and a fixed beacon. You can set `CIRCOM_BIN` to select the compiler and `RWACRED_PTAU` to provide an existing phase-2-ready file for the demo build.

## Circuit statement

The implemented circuit publishes the valuation threshold and issuer public key. The signature, valuation, and legal status are private circuit inputs. Algorithms 1 and 2 in the paper list the signature among the public inputs. The released circuit follows the implementation used in the paper experiment.

## Layout

| Path | Content |
| --- | --- |
| `rwacred/` | RWACred protocol, BBS04 group signatures, and Groth16 and pairing integration |
| `zk_circuits/` | RWACred EdDSA, valuation, and legal-status circuit |
| `scripts/` | Dependency setup, circuit build, and synthetic input generation |
| `rwacred_config.sig_fast_demo.json` | Synthetic asset statement and designated-verifier policy |
| `docs/` | Third-party dependency provenance |

## Citation and dependencies

See [CITATION.cff](CITATION.cff) for the title, authors, and venue. [Third-party notices](docs/THIRD_PARTY.md) record the upstream dependencies and their provenance.

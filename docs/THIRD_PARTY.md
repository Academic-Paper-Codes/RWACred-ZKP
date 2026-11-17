# Third-party provenance

| Component | Source and revision | How this artifact uses it |
| --- | --- | --- |
| Circom | [iden3/circom](https://github.com/iden3/circom), 2.2.3 | External compiler |
| circomlib | [iden3/circomlib](https://github.com/iden3/circomlib), 2.0.2 | npm dependency for circuit templates. The npm package declares GPL-3.0 |
| circomlibjs | [iden3/circomlibjs](https://github.com/iden3/circomlibjs), 0.1.7 | npm dependency for EdDSA and Poseidon |
| snarkjs | [iden3/snarkjs](https://github.com/iden3/snarkjs), 0.7.6 | npm dependency for Groth16 |
| pypbc | [Jemtaly/pypbc](https://github.com/Jemtaly/pypbc/tree/ee629b4863a2d0d5b1d3c5594f6de9c6e7aa2cd6), `ee629b4863a2d0d5b1d3c5594f6de9c6e7aa2cd6` | Fetched for the macOS binding build |
| GMP and PBC | [GMP](https://gmplib.org/), 6.3.0 and [Stanford PBC](https://crypto.stanford.edu/pbc/), 0.5.14 | Fetched for the pairing backend |
| GNU M4 | [GNU M4](https://www.gnu.org/software/m4/), 1.4.19 | Built by the installer when the system M4 is unavailable or fails its compatibility check |

See `package-lock.json` for exact npm transitive dependency versions. The setup scripts fetch third-party libraries under their upstream terms.

#!/usr/bin/env node
"use strict";

const circomlibjs = require("circomlibjs");

async function main() {
  const eddsa = await circomlibjs.buildEddsa();
  const poseidon = await circomlibjs.buildPoseidon();
  const F = poseidon.F;

  const threshold = 300000n;
  const valuation = 500000n;
  const legalStatus = 1n;

  const prv = Buffer.from(
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
    "hex",
  );

  const issuerPub = eddsa.prv2pub(prv);
  const assetHash = poseidon([valuation, legalStatus]);
  const sig = eddsa.signPoseidon(prv, assetHash);

  if (!eddsa.verifyPoseidon(assetHash, sig, issuerPub)) {
    throw new Error("failed to self-verify generated EdDSA Poseidon sample");
  }

  const toDec = (x) => F.toObject(x).toString();

  const payload = {
    issuer_ax: toDec(issuerPub[0]),
    issuer_ay: toDec(issuerPub[1]),
    valuation: valuation.toString(),
    legal_status: legalStatus.toString(),
    sig_r8x: toDec(sig.R8[0]),
    sig_r8y: toDec(sig.R8[1]),
    sig_s: sig.S.toString(),
    d: threshold.toString(),
  };

  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

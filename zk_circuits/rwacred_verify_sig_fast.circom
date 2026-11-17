pragma circom 2.0.2;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/eddsaposeidon.circom";

template RWACredVerifySigFast() {
    signal input d;
    signal input issuer_ax;
    signal input issuer_ay;

    signal input valuation;
    signal input legal_status;

    signal input sig_r8x;
    signal input sig_r8y;
    signal input sig_s;

    // Enforce the boolean claim.
    legal_status * (legal_status - 1) === 0;
    legal_status === 1;

    // Enforce valuation > d over 64-bit values.
    component gt = LessThan(64);
    gt.in[0] <== d;
    gt.in[1] <== valuation;
    gt.out === 1;

    // Bind the issuer signature to the hidden asset attributes.
    component asset_hash = Poseidon(2);
    asset_hash.inputs[0] <== valuation;
    asset_hash.inputs[1] <== legal_status;

    component verifier = EdDSAPoseidonVerifier();
    verifier.enabled <== 1;
    verifier.Ax <== issuer_ax;
    verifier.Ay <== issuer_ay;
    verifier.R8x <== sig_r8x;
    verifier.R8y <== sig_r8y;
    verifier.S <== sig_s;
    verifier.M <== asset_hash.out;
}

component main {public [d, issuer_ax, issuer_ay]} = RWACredVerifySigFast();

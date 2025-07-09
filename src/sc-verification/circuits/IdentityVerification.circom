pragma circom 2.0.0;

include "../../../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../../../node_modules/circomlib/circuits/poseidon.circom";

template IdentityVerification () {  

    // Declaration of signals.  
       
    signal input publicKey[2];

    signal input signature_R8[2];
    signal input signature_S;

    signal input firstName;
    signal input secondName;
    signal input dob;
    signal input nationality;

    signal output IDHash; 

    // Constraints.  

    component poseidon = Poseidon(4);

    poseidon.inputs[0] <== firstName;
    poseidon.inputs[1] <== secondName;
    poseidon.inputs[2] <== dob;
    poseidon.inputs[3] <== nationality;

    component verifier = EdDSAPoseidonVerifier();
    verifier.enabled <== 1;
    verifier.Ax <== publicKey[0];
    verifier.Ay <== publicKey[1];
    verifier.R8x <== signature_R8[0];
    verifier.R8y <== signature_R8[1];
    verifier.S <== signature_S;
    verifier.M <== poseidon.out;

    IDHash <== poseidon.out;
}

component main = IdentityVerification();
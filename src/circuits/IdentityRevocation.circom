pragma circom 2.2.2;

include "../../node_modules/circomlib/circuits/eddsaposeidon.circom";

template IdentityRevocation() {
    signal input challengeDomain;

    signal input holderPubKey[2];
    signal input revokeSignatureR8[2];
    signal input revokeSignatureS;

    signal input contractAddressField;
    signal input chainId;
    signal input hashID;
    signal input challengeBlock;

    component revokeMessageHasher = Poseidon(5);
    revokeMessageHasher.inputs[0] <== challengeDomain;
    revokeMessageHasher.inputs[1] <== contractAddressField;
    revokeMessageHasher.inputs[2] <== chainId;
    revokeMessageHasher.inputs[3] <== hashID;
    revokeMessageHasher.inputs[4] <== challengeBlock;

    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;
    sigVerifier.Ax <== holderPubKey[0];
    sigVerifier.Ay <== holderPubKey[1];
    sigVerifier.R8x <== revokeSignatureR8[0];
    sigVerifier.R8y <== revokeSignatureR8[1];
    sigVerifier.S <== revokeSignatureS;
    sigVerifier.M <== revokeMessageHasher.out;

}

component main {public [hashID, challengeBlock, holderPubKey]} = IdentityRevocation();

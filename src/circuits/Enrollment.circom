pragma circom 2.2.2;

include "../../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";

// Verifies a VC signature and computes a privacy-preserving identity hash.
// The signed message is computed INSIDE the circuit from VC fields,
// preventing users from providing arbitrary signatures.
template Enrollment() {  
    // VC fields
    signal input vcId;
    signal input credentialSubjectId;
    signal input credentialSubjectName;
    signal input credentialSubjectDob;
    signal input credentialSubjectSex;
    signal input credentialSubjectNationality;
    signal input validFrom;
    signal input validUntil;
    signal input issuer;
    signal input sketchHash;
    signal input biometricVk[2];

    // EdDSA signature
    signal input signerPubKey[2];
    signal input signatureR8[2];
    signal input signatureS;
    
    // Public outputs
    signal output hashID;
    signal output outIssuer;
    signal output outValidUntil;
    signal output outSketchHash;
    signal output outVerificationKey[2];
    signal output outSignerPubKey[2];
    
    // Step 1: Compute signed message hash from all VC fields
    component messageHasher = Poseidon(12);
    messageHasher.inputs[0] <== vcId;
    messageHasher.inputs[1] <== credentialSubjectId;
    messageHasher.inputs[2] <== credentialSubjectName;
    messageHasher.inputs[3] <== credentialSubjectDob;
    messageHasher.inputs[4] <== credentialSubjectSex;
    messageHasher.inputs[5] <== credentialSubjectNationality;
    messageHasher.inputs[6] <== validFrom;
    messageHasher.inputs[7] <== issuer;
    messageHasher.inputs[8] <== validUntil;
    messageHasher.inputs[9] <== sketchHash;
    messageHasher.inputs[10] <== biometricVk[0];
    messageHasher.inputs[11] <== biometricVk[1];
    
    signal computedMessage <== messageHasher.out;
    
    // Step 2: Verify signature against computed message
    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;
    sigVerifier.Ax <== signerPubKey[0];
    sigVerifier.Ay <== signerPubKey[1];
    sigVerifier.R8x <== signatureR8[0];
    sigVerifier.R8y <== signatureR8[1];
    sigVerifier.S <== signatureS;
    sigVerifier.M <== computedMessage;
    
    // Step 3: Compute HashID from identity fields
    component hashComputer = Poseidon(7);
    hashComputer.inputs[0] <== vcId;
    hashComputer.inputs[1] <== credentialSubjectId;
    hashComputer.inputs[2] <== credentialSubjectName;
    hashComputer.inputs[3] <== credentialSubjectDob;
    hashComputer.inputs[4] <== credentialSubjectSex;
    hashComputer.inputs[5] <== credentialSubjectNationality;
    hashComputer.inputs[6] <== validFrom;
    
    hashID <== hashComputer.out;
    
    // Step 4: Assign public outputs
    outIssuer <== issuer;
    outValidUntil <== validUntil;
    outSketchHash <== sketchHash;
    outVerificationKey[0] <== biometricVk[0];
    outVerificationKey[1] <== biometricVk[1];
    outSignerPubKey[0] <== signerPubKey[0];
    outSignerPubKey[1] <== signerPubKey[1];
}


component main = Enrollment();

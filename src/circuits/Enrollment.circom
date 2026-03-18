pragma circom 2.2.2;

include "../../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";

// Number of VC fields (before padding)
// Labels: biometricVk.0, biometricVk.1, credentialSubjectId, dob, issuer, name, nationality, sex, sketchHash, validFrom, validUntil, vcId
#define NUM_FIELDS 12
// Padded to power of 2 for Merkle tree
#define NUM_LEAVES 16
// Merkle tree depth = log2(16) = 4
#define TREE_DEPTH 4

// Compute Merkle root from leaves using Poseidon
template MerkleRoot(levels) {
    signal input leaves[1 << levels];
    signal output root;

    var numNodes = (1 << levels) - 1;
    signal nodes[numNodes];

    // First level: hash pairs of leaves
    var halfLeaves = 1 << (levels - 1);
    component leafHashers[halfLeaves];
    for (var i = 0; i < halfLeaves; i++) {
        leafHashers[i] = Poseidon(2);
        leafHashers[i].inputs[0] <== leaves[2*i];
        leafHashers[i].inputs[1] <== leaves[2*i + 1];
        nodes[i] <== leafHashers[i].out;
    }

    // Remaining levels
    var offset = 0;
    var prevOffset = 0;
    for (var level = levels - 2; level >= 0; level--) {
        var numPairs = 1 << level;
        offset = prevOffset + (1 << (level + 1));
        component nodeHashers[numPairs];
        for (var i = 0; i < numPairs; i++) {
            nodeHashers[i] = Poseidon(2);
            nodeHashers[i].inputs[0] <== nodes[prevOffset + 2*i];
            nodeHashers[i].inputs[1] <== nodes[prevOffset + 2*i + 1];
            nodes[offset + i] <== nodeHashers[i].out;
        }
        prevOffset = offset;
    }

    root <== nodes[numNodes - 1];
}

// Compute a labeled leaf hash: Poseidon(labelField, value)
template LabeledLeaf() {
    signal input labelField;
    signal input value;
    signal output leaf;

    component hasher = Poseidon(2);
    hasher.inputs[0] <== labelField;
    hasher.inputs[1] <== value;
    leaf <== hasher.out;
}

// Verifies a VC signature using Merkle tree structure with domain separation.
// The signed message is: Poseidon(domainSeparator, merkleRoot)
template Enrollment() {
    // Domain separator (precomputed from "eddsa-babyjubjub-poseidon-2024:v1")
    signal input domainSeparator;
    
    // Merkle leaves (precomputed: Poseidon(label, value) for each field)
    signal input merkleLeaves[NUM_LEAVES];
    
    // Raw field values for computing hashID and public outputs
    // Order matches VC_FIELD_LABELS: biometricVk.0, biometricVk.1, credentialSubjectId, dob, issuer, name, nationality, sex, sketchHash, validFrom, validUntil, vcId
    signal input fieldValues[NUM_FIELDS];

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
    
    // Field label constants (precomputed from stringToFieldSimple() in did.ts)
    var labelBiometricVk0 = 7796990559804582209388911734320;
    var labelBiometricVk1 = 7796990559804582209388911734321;
    var labelCredentialSubjectId = 2217739077219273223255122644505107646662330724;
    var labelDob = 6582114;
    var labelIssuer = 115944579229042;
    var labelName = 1851878757;
    var labelNationality = 133442057126172576218444921;
    var labelSex = 7562616;
    var labelSketchHash = 545053257723290792850280;
    var labelValidFrom = 2183735902496290402157;
    var labelValidUntil = 559036391039114700679532;
    var labelVcId = 1986218340;
    
    // Step 1: Verify leaf computation (each leaf = Poseidon(label, value))
    component leafVerifiers[NUM_FIELDS];
    
    leafVerifiers[0] = LabeledLeaf();
    leafVerifiers[0].labelField <== labelBiometricVk0;
    leafVerifiers[0].value <== fieldValues[0];
    leafVerifiers[0].leaf === merkleLeaves[0];
    
    leafVerifiers[1] = LabeledLeaf();
    leafVerifiers[1].labelField <== labelBiometricVk1;
    leafVerifiers[1].value <== fieldValues[1];
    leafVerifiers[1].leaf === merkleLeaves[1];
    
    leafVerifiers[2] = LabeledLeaf();
    leafVerifiers[2].labelField <== labelCredentialSubjectId;
    leafVerifiers[2].value <== fieldValues[2];
    leafVerifiers[2].leaf === merkleLeaves[2];
    
    leafVerifiers[3] = LabeledLeaf();
    leafVerifiers[3].labelField <== labelDob;
    leafVerifiers[3].value <== fieldValues[3];
    leafVerifiers[3].leaf === merkleLeaves[3];
    
    leafVerifiers[4] = LabeledLeaf();
    leafVerifiers[4].labelField <== labelIssuer;
    leafVerifiers[4].value <== fieldValues[4];
    leafVerifiers[4].leaf === merkleLeaves[4];
    
    leafVerifiers[5] = LabeledLeaf();
    leafVerifiers[5].labelField <== labelName;
    leafVerifiers[5].value <== fieldValues[5];
    leafVerifiers[5].leaf === merkleLeaves[5];
    
    leafVerifiers[6] = LabeledLeaf();
    leafVerifiers[6].labelField <== labelNationality;
    leafVerifiers[6].value <== fieldValues[6];
    leafVerifiers[6].leaf === merkleLeaves[6];
    
    leafVerifiers[7] = LabeledLeaf();
    leafVerifiers[7].labelField <== labelSex;
    leafVerifiers[7].value <== fieldValues[7];
    leafVerifiers[7].leaf === merkleLeaves[7];
    
    leafVerifiers[8] = LabeledLeaf();
    leafVerifiers[8].labelField <== labelSketchHash;
    leafVerifiers[8].value <== fieldValues[8];
    leafVerifiers[8].leaf === merkleLeaves[8];
    
    leafVerifiers[9] = LabeledLeaf();
    leafVerifiers[9].labelField <== labelValidFrom;
    leafVerifiers[9].value <== fieldValues[9];
    leafVerifiers[9].leaf === merkleLeaves[9];
    
    leafVerifiers[10] = LabeledLeaf();
    leafVerifiers[10].labelField <== labelValidUntil;
    leafVerifiers[10].value <== fieldValues[10];
    leafVerifiers[10].leaf === merkleLeaves[10];
    
    leafVerifiers[11] = LabeledLeaf();
    leafVerifiers[11].labelField <== labelVcId;
    leafVerifiers[11].value <== fieldValues[11];
    leafVerifiers[11].leaf === merkleLeaves[11];
    
    // Step 2: Compute Merkle root from leaves
    component merkleRoot = MerkleRoot(TREE_DEPTH);
    for (var i = 0; i < NUM_LEAVES; i++) {
        merkleRoot.leaves[i] <== merkleLeaves[i];
    }
    
    // Step 3: Compute signed message = Poseidon(domainSeparator, merkleRoot)
    component messageHasher = Poseidon(2);
    messageHasher.inputs[0] <== domainSeparator;
    messageHasher.inputs[1] <== merkleRoot.root;
    signal computedMessage <== messageHasher.out;
    
    // Step 4: Verify signature against computed message
    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;
    sigVerifier.Ax <== signerPubKey[0];
    sigVerifier.Ay <== signerPubKey[1];
    sigVerifier.R8x <== signatureR8[0];
    sigVerifier.R8y <== signatureR8[1];
    sigVerifier.S <== signatureS;
    sigVerifier.M <== computedMessage;
    
    // Step 5: Compute HashID from identity fields
    // Using: vcId, credentialSubjectId, name, dob, sex, nationality, validFrom
    component hashComputer = Poseidon(7);
    hashComputer.inputs[0] <== fieldValues[11]; // vcId
    hashComputer.inputs[1] <== fieldValues[2];  // credentialSubjectId
    hashComputer.inputs[2] <== fieldValues[5];  // name
    hashComputer.inputs[3] <== fieldValues[3];  // dob
    hashComputer.inputs[4] <== fieldValues[7];  // sex
    hashComputer.inputs[5] <== fieldValues[6];  // nationality
    hashComputer.inputs[6] <== fieldValues[9];  // validFrom
    
    hashID <== hashComputer.out;
    
    // Step 6: Assign public outputs
    outIssuer <== fieldValues[4];              // issuer
    outValidUntil <== fieldValues[10];         // validUntil
    outSketchHash <== fieldValues[8];          // sketchHash
    outVerificationKey[0] <== fieldValues[0];  // biometricVk.0
    outVerificationKey[1] <== fieldValues[1];  // biometricVk.1
    outSignerPubKey[0] <== signerPubKey[0];
    outSignerPubKey[1] <== signerPubKey[1];
}


component main = Enrollment();

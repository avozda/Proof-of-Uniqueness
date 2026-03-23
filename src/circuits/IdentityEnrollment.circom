pragma circom 2.2.2;

include "../../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../../node_modules/circomlib/circuits/smt/smthash_poseidon.circom";

// IdentityEnrollment(numFields, treeDepth): VC has numFields labeled leaves; Merkle tree has 2^treeDepth leaves (pad extras with 0).
// Circomlib has SMT helpers, not a dense Merkle builder; SMTHash2 is Poseidon(L,R) and matches our internal node hashing.

// Binary Merkle root over 2^levels leaves (predeclare hashers; Circom forbids `component` inside unknown loops).
template MerkleRoot(levels) {
    signal input leaves[1 << levels];
    signal output root;

    var n = 1 << levels;
    var totalHashers = n - 1;
    component hashers[totalHashers];
    signal nodes[totalHashers];

    var writeIdx = 0;
    var curOut = n >> 1;
    for (var i = 0; i < curOut; i++) {
        hashers[writeIdx] = SMTHash2();
        hashers[writeIdx].L <== leaves[2*i];
        hashers[writeIdx].R <== leaves[2*i + 1];
        nodes[writeIdx] <== hashers[writeIdx].out;
        writeIdx++;
    }

    var readStart = 0;
    var readCount = curOut >> 1;
    for (var lvl = 1; lvl < levels; lvl++) {
        for (var i = 0; i < readCount; i++) {
            hashers[writeIdx] = SMTHash2();
            hashers[writeIdx].L <== nodes[readStart + 2*i];
            hashers[writeIdx].R <== nodes[readStart + 2*i + 1];
            nodes[writeIdx] <== hashers[writeIdx].out;
            writeIdx++;
        }
        readStart = readStart + (readCount << 1);
        readCount = readCount >> 1;
    }

    root <== nodes[totalHashers - 1];
}

// Labeled leaf = SMTHash2(labelConst, value); label is a compile-time constant (stringToFieldSimple in did.ts).
template LabeledLeaf(labelConst) {
    signal input value;
    signal output leaf;

    component hasher = SMTHash2();
    hasher.L <== labelConst;
    hasher.R <== value;
    leaf <== hasher.out;
}

// Verifies a VC signature using Merkle tree structure with domain separation.
// The signed message is: Poseidon(domainSeparator, merkleRoot)
template IdentityEnrollment(numFields, treeDepth) {
    var numLeaves = 1 << treeDepth;

    // Domain separator (precomputed from SIGNATURE_DOMAIN in did.ts; ≤31 bytes for single field element)
    signal input domainSeparator;
    
    // Merkle leaves (precomputed: Poseidon(label, value) for each field)
    signal input merkleLeaves[numLeaves];
    
    // Raw field values for computing hashID and public outputs
    // Order matches VC_FIELD_LABELS: biometricVk.0, biometricVk.1, credentialSubjectId, dob, issuer, name, nationality, sex, sketchHash, validFrom, validUntil, vcId
    signal input fieldValues[numFields];

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
    
    // Field label constants (precomputed from stringToFieldSimple() in did.ts); order = VC_FIELD_LABELS
    var fieldLabels[numFields];
    fieldLabels[0] = 7796990559804582209388911734320;       // biometricVk.0
    fieldLabels[1] = 7796990559804582209388911734321;       // biometricVk.1
    fieldLabels[2] = 2217739077219273223255122644505107646662330724; // credentialSubjectId
    fieldLabels[3] = 6582114;                               // dob
    fieldLabels[4] = 115944579229042;                       // issuer
    fieldLabels[5] = 1851878757;                             // name
    fieldLabels[6] = 133442057126172576218444921;           // nationality
    fieldLabels[7] = 7562616;                               // sex
    fieldLabels[8] = 545053257723290792850280;               // sketchHash
    fieldLabels[9] = 2183735902496290402157;                // validFrom
    fieldLabels[10] = 559036391039114700679532;             // validUntil
    fieldLabels[11] = 1986218340;                           // vcId

    // Step 1: each leaf must equal SMTHash2(label, fieldValues[i])
    component leafVerifiers[numFields];
    for (var i = 0; i < numFields; i++) {
        leafVerifiers[i] = LabeledLeaf(fieldLabels[i]);
        leafVerifiers[i].value <== fieldValues[i];
        leafVerifiers[i].leaf === merkleLeaves[i];
    }
    
    // Step 2: Compute Merkle root from leaves
    component merkleRoot = MerkleRoot(treeDepth);
    for (var i = 0; i < numLeaves; i++) {
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


// 12 VC fields; Merkle tree depth 4 => 16 leaves (pad unused with 0)
component main = IdentityEnrollment(12, 4);

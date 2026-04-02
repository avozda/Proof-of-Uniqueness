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
    // Order matches VC_FIELD_LABELS: holderPubKey.0, holderPubKey.1, credentialSubjectId, dob, issuer, name, nationality, permanentAddressHash, placeOfBirth, sex, validFrom, validUntil, vcId
    signal input fieldValues[numFields];

    // EdDSA signature
    signal input signerPubKey[2];
    signal input signatureR8[2];
    signal input signatureS;

    // Holder EdDSA signature over credentialSubjectId binding
    signal input holderSignatureR8[2];
    signal input holderSignatureS;
    
    // Public outputs
    signal output hashID;
    signal output outIssuer;
    signal output outValidUntil;
    signal output outHolderPubKey[2];
    signal output outSignerPubKey[2];

    var holderDomainSeparator = 167820972663910113509713736073221657714819440573153347582457393; // "holder-bjj-bind-subject:v1"
    
    // Field label constants (precomputed from stringToFieldSimple() in did.ts); order = VC_FIELD_LABELS
    var fieldLabels[numFields];
    fieldLabels[0] = 2118198470571567473536145588563504;     // holderPubKey.0
    fieldLabels[1] = 2118198470571567473536145588563505;     // holderPubKey.1
    fieldLabels[2] = 2217739077219273223255122644505107646662330724; // credentialSubjectId
    fieldLabels[3] = 6582114;                               // dob
    fieldLabels[4] = 115944579229042;                       // issuer
    fieldLabels[5] = 1851878757;                             // name
    fieldLabels[6] = 133442057126172576218444921;           // nationality
    fieldLabels[7] = 641669309618204160221840285997001192639266124648; // permanentAddressHash
    fieldLabels[8] = 34793344991585695257288930408;         // placeOfBirth
    fieldLabels[9] = 7562616;                               // sex
    fieldLabels[10] = 2183735902496290402157;               // validFrom
    fieldLabels[11] = 559036391039114700679532;             // validUntil
    fieldLabels[12] = 1986218340;                           // vcId

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

    // Step 4b: Verify holder signature over subject binding message
    component holderMessageHasher = Poseidon(2);
    holderMessageHasher.inputs[0] <== holderDomainSeparator;
    holderMessageHasher.inputs[1] <== fieldValues[2]; // credentialSubjectId

    component holderSigVerifier = EdDSAPoseidonVerifier();
    holderSigVerifier.enabled <== 1;
    holderSigVerifier.Ax <== fieldValues[0]; // holder key x
    holderSigVerifier.Ay <== fieldValues[1]; // holder key y
    holderSigVerifier.R8x <== holderSignatureR8[0];
    holderSigVerifier.R8y <== holderSignatureR8[1];
    holderSigVerifier.S <== holderSignatureS;
    holderSigVerifier.M <== holderMessageHasher.out;

    // Step 5: Compute HashID from identity fields
    // Include holder signature commitment so leaked VC fields alone cannot derive hashID.
    component holderSigCommitment = Poseidon(3);
    holderSigCommitment.inputs[0] <== holderSignatureR8[0];
    holderSigCommitment.inputs[1] <== holderSignatureR8[1];
    holderSigCommitment.inputs[2] <== holderSignatureS;

    component hashComputer = Poseidon(10);
    hashComputer.inputs[0] <== fieldValues[12]; // vcId
    hashComputer.inputs[1] <== fieldValues[2];  // credentialSubjectId
    hashComputer.inputs[2] <== fieldValues[5];  // name
    hashComputer.inputs[3] <== fieldValues[3];  // dob
    hashComputer.inputs[4] <== fieldValues[8];  // placeOfBirth
    hashComputer.inputs[5] <== fieldValues[9];  // sex
    hashComputer.inputs[6] <== fieldValues[6];  // nationality
    hashComputer.inputs[7] <== fieldValues[7];  // permanentAddressHash
    hashComputer.inputs[8] <== fieldValues[10]; // validFrom
    hashComputer.inputs[9] <== holderSigCommitment.out;
    
    hashID <== hashComputer.out;
    
    // Step 6: Assign public outputs
    outIssuer <== fieldValues[4];              // issuer
    outValidUntil <== fieldValues[11];         // validUntil
    outHolderPubKey[0] <== fieldValues[0];     // holderPubKey.0
    outHolderPubKey[1] <== fieldValues[1];     // holderPubKey.1
    outSignerPubKey[0] <== signerPubKey[0];
    outSignerPubKey[1] <== signerPubKey[1];
}


// 13 VC fields; Merkle tree depth 4 => 16 leaves (pad unused with 0)
component main = IdentityEnrollment(13, 4);

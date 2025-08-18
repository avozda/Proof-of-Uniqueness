pragma circom 2.2.2;

include "../../../node_modules/circomlib/circuits/poseidon.circom";
include "../../../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../../../node_modules/circomlib/circuits/smt/smtprocessor.circom";
include "../../../node_modules/circomlib/circuits/bitify.circom";
include "../../../node_modules/circomlib/circuits/comparators.circom";

// Template for SMT non-membership verification and insertion
template SMTVerification () {  
    
    // Inputs for SMT verification
    signal input hashID;            // HashID to check for uniqueness and insert
    signal input oldRoot;           // Current SMT root
    signal input siblings[254];     // Merkle proof siblings for depth 254 (circomlib standard)
    
    // Outputs
    signal output newRoot;          // New SMT root after insertion
    signal output verifiedHashID;  // The hashID that was verified and inserted
    signal output publicOldRoot;
    
    
    // Step 1: Verify non-membership in SMT using the hashID
    component smtVerifier = SMTVerifier(254);
    smtVerifier.enabled <== 1; // Always enabled since we're only doing SMT verification
    smtVerifier.root <== oldRoot;
    
    // Set up siblings for merkle proof
    for (var i = 0; i < 254; i++) {
        smtVerifier.siblings[i] <== siblings[i];
    }
    
    smtVerifier.oldKey <== 0; // Not used when isOld0 = 1 (empty position)
    smtVerifier.oldValue <== 0; // Value at empty position
    smtVerifier.isOld0 <== 1; // Always 1 - proving the position is empty (uniqueness)
    smtVerifier.key <== hashID; // Use hashID as the key to check
    smtVerifier.value <== 0; // Set to 0 for non-membership proof (value doesn't matter)
    smtVerifier.fnc <== 1; // 1 = verify non-inclusion
    
    // Step 2: Use SMT processor to calculate new root after insertion
    component smtProcessor = SMTProcessor(254);
    smtProcessor.oldRoot <== oldRoot;
    
    // Set up siblings for merkle proof (same as verifier)
    for (var i = 0; i < 254; i++) {
        smtProcessor.siblings[i] <== siblings[i];
    }
    
    smtProcessor.oldKey <== 0; // Not used when isOld0 = 1 (empty position)
    smtProcessor.oldValue <== 0; // Should be 0 for empty position
    smtProcessor.isOld0 <== 1; // Always 1 - proving the position is empty
    smtProcessor.newKey <== hashID; // Insert the hashID as new key
    smtProcessor.newValue <== 1; // Mark as present with value 1
    smtProcessor.fnc[0] <== 1; // fnc[0] = 1 for INSERT operation
    smtProcessor.fnc[1] <== 0; // fnc[1] = 0 for INSERT operation
    
    // Outputs
    newRoot <== smtProcessor.newRoot;
    verifiedHashID <== hashID; // Output the hashID that was verified for uniqueness
    publicOldRoot <== oldRoot;
}

component main = SMTVerification();
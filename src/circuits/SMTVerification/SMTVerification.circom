pragma circom 2.2.2;

include "../../../node_modules/circomlib/circuits/poseidon.circom";
include "../../../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../../../node_modules/circomlib/circuits/smt/smtprocessor.circom";
include "../../../node_modules/circomlib/circuits/bitify.circom";
include "../../../node_modules/circomlib/circuits/comparators.circom";

template SMTVerification () {  
    
    // Inputs
    signal input hashID;
    signal input oldRoot;
    signal input siblings[254];
    signal input isOld0;
    signal input oldKey;
    
    // Outputs
    signal output newRoot;
    signal output verifiedHashID;
    signal output publicOldRoot;
    
    // Use SMT processor to calculate new root after insertion
    component smtProcessor = SMTProcessor(254);
    smtProcessor.oldRoot <== oldRoot;
    
    for (var i = 0; i < 254; i++) {
        smtProcessor.siblings[i] <== siblings[i];
    }
    
    smtProcessor.oldKey <== oldKey;
    smtProcessor.isOld0 <== isOld0;
    smtProcessor.newKey <== hashID;
    smtProcessor.oldValue <== 1;
    smtProcessor.newValue <== 1;
    smtProcessor.fnc[0] <== 1;
    smtProcessor.fnc[1] <== 0;
    
    // Outputs
    newRoot <== smtProcessor.newRoot;
    verifiedHashID <== hashID;
    publicOldRoot <== oldRoot;
}

component main = SMTVerification();
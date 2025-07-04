pragma circom 2.0.0;

include "../../../node_modules/circomlib/circuits/poseidon.circom";

template IDHash () {  

    // Declaration of signals.  
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

    IDHash <== poseidon.out;
}

component main = IDHash();
pragma circom 2.2.2;

include "../../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";

/**
 * Enrollment Circuit
 * 
 * This circuit verifies a Verifiable Credential signature and computes
 * a privacy-preserving hash of the identity claim.
 *
 * SECURITY: The signed message is computed INSIDE the circuit from the VC fields,
 * ensuring the signature must have been created over exactly these fields.
 * Users cannot provide arbitrary signatures unrelated to the identity data.
 *
 * Inputs (private):
 *   - VC fields for hash computation
 *   - Signature components for verification
 *
 * Outputs (public):
 *   - HashID: Poseidon hash of identity fields
 *   - issuer: The credential issuer identifier
 *   - validUntil: Expiration timestamp
 *   - sketchHash: Hash of the biometric sketch
 *   - verificationKey: The biometric verification key (2 field elements)
 *   - signerPubKey: The issuer's public key (for trust verification)
 */
template Enrollment() {  
    // ========================================
    // Input signals for VC fields
    // ========================================
    
    // VC identifier (urn:uuid:...)
    signal input vcId;
    
    // Credential subject fields
    signal input credentialSubjectId;      // credentialSubject.id
    signal input credentialSubjectName;    // credentialSubject.name (hashed to field)
    signal input credentialSubjectDob;     // credentialSubject.dateOfBirth (as timestamp or encoded)
    signal input credentialSubjectSex;     // credentialSubject.sex (encoded: 0=male, 1=female, 2=other)
    signal input credentialSubjectNationality; // credentialSubject.nationality (hashed to field)
    
    // Validity period
    signal input validFrom;                // validFrom timestamp
    signal input validUntil;               // validUntil timestamp
    
    // Issuer identifier
    signal input issuer;                   // issuer.id (hashed to field)
    
    // Biometric template data
    signal input sketchHash;               // Hash of biometric sketch (too large for direct input)
    signal input biometricVk[2];           // Biometric verification key (compressed point: x, y)
    
    // ========================================
    // Signature verification inputs
    // ========================================
    
    // EdDSA public key (issuer's signing key)
    signal input signerPubKey[2];          // Public key [Ax, Ay]
    
    // EdDSA signature components
    signal input signatureR8[2];           // R8 point [x, y]
    signal input signatureS;               // S scalar
    
    // NOTE: signedMessage is NOT an input - it's computed inside the circuit
    // This prevents users from providing arbitrary signatures
    
    // ========================================
    // Public output signals
    // ========================================
    
    signal output hashID;                  // Privacy-preserving identity hash
    signal output outIssuer;               // Issuer identifier
    signal output outValidUntil;           // Expiration timestamp
    signal output outSketchHash;           // Biometric sketch hash
    signal output outVerificationKey[2];   // Biometric verification key
    signal output outSignerPubKey[2];      // Issuer's public key (for trust verification)
    
    // ========================================
    // Step 1: Compute the signed message hash from ALL VC fields
    // ========================================
    // This ensures the signature was created over exactly these fields
    // Message = Poseidon(vcId, subjectId, name, dob, sex, nationality, validFrom, issuer, validUntil, sketchHash, vk[0], vk[1])
    
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
    
    // ========================================
    // Step 2: Verify VC Signature against computed message
    // ========================================
    
    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;
    sigVerifier.Ax <== signerPubKey[0];
    sigVerifier.Ay <== signerPubKey[1];
    sigVerifier.R8x <== signatureR8[0];
    sigVerifier.R8y <== signatureR8[1];
    sigVerifier.S <== signatureS;
    sigVerifier.M <== computedMessage;  // Use computed message, NOT user input
    
    // ========================================
    // Step 3: Compute HashID from identity fields
    // ========================================
    // HashID = Poseidon(vcId, credentialSubjectId, name, dob, sex, nationality, validFrom)
    // This is a subset of fields for the privacy-preserving identity hash
    
    component hashComputer = Poseidon(7);
    hashComputer.inputs[0] <== vcId;
    hashComputer.inputs[1] <== credentialSubjectId;
    hashComputer.inputs[2] <== credentialSubjectName;
    hashComputer.inputs[3] <== credentialSubjectDob;
    hashComputer.inputs[4] <== credentialSubjectSex;
    hashComputer.inputs[5] <== credentialSubjectNationality;
    hashComputer.inputs[6] <== validFrom;
    
    hashID <== hashComputer.out;
    
    // ========================================
    // Step 4: Assign public outputs
    // ========================================
    
    outIssuer <== issuer;
    outValidUntil <== validUntil;
    outSketchHash <== sketchHash;
    outVerificationKey[0] <== biometricVk[0];
    outVerificationKey[1] <== biometricVk[1];
    
    // Output signer's public key so verifiers can check if they trust this issuer
    outSignerPubKey[0] <== signerPubKey[0];
    outSignerPubKey[1] <== signerPubKey[1];
}


component main = Enrollment();

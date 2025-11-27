// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Groth16Verifier} from "./Groth16Verifier.sol";

/**
 * @title ProofOfUniqueness
 * @notice Contract for managing biometric identity enrollments with ZK proof verification
 * @dev Uses Groth16 proofs to verify identity claims without revealing private data
 */
contract ProofOfUniqueness {
    // ============ Structs ============

    struct IdentityRecord {
        uint256 validUntil;
        uint256 issuerPubKeyX; // Signer's public key X coordinate
        uint256 issuerPubKeyY; // Signer's public key Y coordinate
        uint256 verificationKeyX;
        uint256 verificationKeyY;
        uint256 sketchHash;
        bool exists;
    }

    // ============ State Variables ============

    /// @notice The Groth16 verifier contract
    Groth16Verifier public immutable verifier;

    /// @notice Mapping of hashID to identity records
    mapping(uint256 => IdentityRecord) public identities;

    /// @notice Mapping of trusted issuer public keys (hash of pubKeyX and pubKeyY)
    mapping(uint256 => bool) public trustedIssuers;

    /// @notice Mapping of contract owners/admins
    mapping(address => bool) public owners;

    /// @notice Array of all registered hashIDs for enumeration
    uint256[] public registeredHashIDs;

    // ============ Events ============

    event IdentityEnrolled(
        uint256 indexed hashID,
        uint256 indexed issuerPubKeyHash,
        uint256 validUntil
    );

    event IssuerAdded(uint256 indexed issuerPubKeyHash);
    event IssuerRemoved(uint256 indexed issuerPubKeyHash);
    event OwnerAdded(address indexed owner);
    event OwnerRemoved(address indexed owner);

    // ============ Errors ============

    error NotOwner();
    error IssuerNotTrusted();
    error IdentityAlreadyExists();
    error IdentityNotFound();
    error InvalidProof();
    error IdentityExpired();

    // ============ Modifiers ============

    modifier onlyOwner() {
        if (!owners[msg.sender]) revert NotOwner();
        _;
    }

    // ============ Constructor ============

    /**
     * @notice Initialize the contract with a verifier and initial owner
     * @param _verifier Address of the Groth16Verifier contract
     */
    constructor(address _verifier) {
        verifier = Groth16Verifier(_verifier);
        owners[msg.sender] = true;
        emit OwnerAdded(msg.sender);
    }

    // ============ External Functions ============

    /**
     * @notice Enroll a new identity by verifying a ZK proof
     * @param _pA Proof element A
     * @param _pB Proof element B
     * @param _pC Proof element C
     * @param _pubSignals Public signals from the proof:
     *        [0] hashID
     *        [1] issuer (field element)
     *        [2] validUntil
     *        [3] sketchHash
     *        [4] verificationKeyX
     *        [5] verificationKeyY
     *        [6] signerPubKeyX
     *        [7] signerPubKeyY
     */
    function enroll(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[8] calldata _pubSignals
    ) external {
        // Extract public signals
        uint256 hashID = _pubSignals[0];

        // Check if identity already exists
        if (identities[hashID].exists) revert IdentityAlreadyExists();

        // uint256 issuerField = _pubSignals[1]; // Not used directly, but part of signed data
        uint256 validUntil = _pubSignals[2];
        uint256 sketchHash = _pubSignals[3];
        uint256 verificationKeyX = _pubSignals[4];
        uint256 verificationKeyY = _pubSignals[5];
        uint256 signerPubKeyX = _pubSignals[6];
        uint256 signerPubKeyY = _pubSignals[7];

        // Compute issuer public key hash and check if trusted
        uint256 issuerPubKeyHash = uint256(
            keccak256(abi.encodePacked(signerPubKeyX, signerPubKeyY))
        );
        if (!trustedIssuers[issuerPubKeyHash]) revert IssuerNotTrusted();

        // Verify the ZK proof
        bool isValid = verifier.verifyProof(_pA, _pB, _pC, _pubSignals);
        if (!isValid) revert InvalidProof();

        // Store the identity record
        identities[hashID] = IdentityRecord({
            validUntil: validUntil,
            issuerPubKeyX: signerPubKeyX,
            issuerPubKeyY: signerPubKeyY,
            verificationKeyX: verificationKeyX,
            verificationKeyY: verificationKeyY,
            sketchHash: sketchHash,
            exists: true
        });

        registeredHashIDs.push(hashID);

        emit IdentityEnrolled(hashID, issuerPubKeyHash, validUntil);
    }

    /**
     * @notice Get the sketch hash for a given hashID
     * @param hashID The identity hash ID
     * @return sketchHash The biometric sketch hash
     */
    function getSketchHash(
        uint256 hashID
    ) external view returns (uint256 sketchHash) {
        if (!identities[hashID].exists) revert IdentityNotFound();
        return identities[hashID].sketchHash;
    }

    /**
     * @notice Get the verification key for a given hashID
     * @param hashID The identity hash ID
     * @return vkX Verification key X coordinate
     * @return vkY Verification key Y coordinate
     */
    function getVerificationKey(
        uint256 hashID
    ) external view returns (uint256 vkX, uint256 vkY) {
        if (!identities[hashID].exists) revert IdentityNotFound();
        IdentityRecord storage record = identities[hashID];
        return (record.verificationKeyX, record.verificationKeyY);
    }

    /**
     * @notice Get the full identity record for a given hashID
     * @param hashID The identity hash ID
     * @return record The identity record
     */
    function getIdentity(
        uint256 hashID
    ) external view returns (IdentityRecord memory record) {
        if (!identities[hashID].exists) revert IdentityNotFound();
        return identities[hashID];
    }

    /**
     * @notice Check if an identity is valid (exists and not expired)
     * @param hashID The identity hash ID
     * @return isValid True if identity exists and is not expired
     */
    function isIdentityValid(
        uint256 hashID
    ) external view returns (bool isValid) {
        IdentityRecord storage record = identities[hashID];
        return record.exists && block.timestamp <= record.validUntil;
    }

    /**
     * @notice Get the number of registered identities
     * @return count The number of registered identities
     */
    function getIdentityCount() external view returns (uint256 count) {
        return registeredHashIDs.length;
    }

    // ============ Admin Functions ============

    /**
     * @notice Add a trusted issuer by their public key
     * @param pubKeyX The issuer's public key X coordinate
     * @param pubKeyY The issuer's public key Y coordinate
     */
    function addTrustedIssuer(
        uint256 pubKeyX,
        uint256 pubKeyY
    ) external onlyOwner {
        uint256 issuerPubKeyHash = uint256(
            keccak256(abi.encodePacked(pubKeyX, pubKeyY))
        );
        trustedIssuers[issuerPubKeyHash] = true;
        emit IssuerAdded(issuerPubKeyHash);
    }

    /**
     * @notice Remove a trusted issuer
     * @param pubKeyX The issuer's public key X coordinate
     * @param pubKeyY The issuer's public key Y coordinate
     */
    function removeTrustedIssuer(
        uint256 pubKeyX,
        uint256 pubKeyY
    ) external onlyOwner {
        uint256 issuerPubKeyHash = uint256(
            keccak256(abi.encodePacked(pubKeyX, pubKeyY))
        );
        trustedIssuers[issuerPubKeyHash] = false;
        emit IssuerRemoved(issuerPubKeyHash);
    }

    /**
     * @notice Check if an issuer is trusted
     * @param pubKeyX The issuer's public key X coordinate
     * @param pubKeyY The issuer's public key Y coordinate
     * @return isTrusted True if the issuer is trusted
     */
    function isIssuerTrusted(
        uint256 pubKeyX,
        uint256 pubKeyY
    ) external view returns (bool isTrusted) {
        uint256 issuerPubKeyHash = uint256(
            keccak256(abi.encodePacked(pubKeyX, pubKeyY))
        );
        return trustedIssuers[issuerPubKeyHash];
    }

    /**
     * @notice Add a new owner
     * @param owner The address to add as owner
     */
    function addOwner(address owner) external onlyOwner {
        owners[owner] = true;
        emit OwnerAdded(owner);
    }

    /**
     * @notice Remove an owner
     * @param owner The address to remove as owner
     */
    function removeOwner(address owner) external onlyOwner {
        owners[owner] = false;
        emit OwnerRemoved(owner);
    }
}

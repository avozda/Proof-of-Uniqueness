// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Groth16Verifier} from "./Groth16Verifier.sol";

/**
 * @title IdentityRegistry
 * @notice Contract for managing biometric identity enrollments with ZK proof verification
 * @dev Uses Groth16 proofs to verify identity claims without revealing private data
 */
contract IdentityRegistry {
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

    /// @notice Max age (in blocks) for a revocation challenge
    uint256 public constant MAX_REVOKE_BLOCK_AGE = 20;

    bytes32 private constant REVOKE_DOMAIN =
        keccak256("IdentityRegistry::Revoke:v1");

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
    event IdentityPurged(uint256 indexed hashID, PurgeReason reason);
    event IdentityRevoked(
        uint256 indexed hashID,
        address indexed signer,
        uint256 challengeBlock
    );

    /// @notice Reason for identity purge
    enum PurgeReason {
        Expired,
        UntrustedIssuer
    }

    // ============ Errors ============

    error NotOwner();
    error IssuerNotTrusted();
    error IdentityAlreadyExists();
    error IdentityNotFound();
    error InvalidProof();
    error IdentityExpired();
    error ChallengeBlockInFuture();
    error StaleChallenge();
    error InvalidRevocationSignature();
    error RevocationSignerMismatch();

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
     * @notice Revoke an identity by submitting a signature from the enrolled biometric key
     * @dev Signature challenge binds contract + chain + hashID + challengeBlock
     * @param hashID The identity hash ID to revoke
     * @param challengeBlock The block number that was signed
     * @param v Signature recovery id
     * @param r Signature part r
     * @param s Signature part s
     */
    function revokeIdentity(
        uint256 hashID,
        uint256 challengeBlock,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        IdentityRecord storage record = identities[hashID];
        if (!record.exists) revert IdentityNotFound();

        if (challengeBlock > block.number) revert ChallengeBlockInFuture();
        if (block.number - challengeBlock > MAX_REVOKE_BLOCK_AGE)
            revert StaleChallenge();

        bytes32 challengeDigest = keccak256(
            abi.encode(
                REVOKE_DOMAIN,
                address(this),
                block.chainid,
                hashID,
                challengeBlock
            )
        );

        uint8 vv = v;
        if (vv < 27) vv += 27;
        address recovered = ecrecover(challengeDigest, vv, r, s);
        if (recovered == address(0)) revert InvalidRevocationSignature();

        address expected = _secp256k1Address(
            record.verificationKeyX,
            record.verificationKeyY
        );
        if (recovered != expected) revert RevocationSignerMismatch();

        _deleteIdentity(hashID);
        emit IdentityRevoked(hashID, recovered, challengeBlock);
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

    /**
     * @notice Remove all invalid identity records (expired or from untrusted issuers)
     * @dev Processes in batches to avoid gas limit issues. Call repeatedly until returns 0.
     * @param maxIterations Maximum number of records to check in this call (0 = check all)
     * @return purgedCount Number of records purged in this call
     * @return remainingCount Number of records still to check
     */
    function purgeInvalidRecords(
        uint256 maxIterations
    ) external onlyOwner returns (uint256 purgedCount, uint256 remainingCount) {
        uint256 length = registeredHashIDs.length;
        if (length == 0) return (0, 0);

        uint256 iterations = maxIterations == 0 ? length : maxIterations;
        uint256 i = 0;

        while (i < length && iterations > 0) {
            uint256 hashID = registeredHashIDs[i];
            IdentityRecord storage record = identities[hashID];

            bool shouldPurge = false;
            PurgeReason reason;

            // Check if expired
            if (block.timestamp > record.validUntil) {
                shouldPurge = true;
                reason = PurgeReason.Expired;
            } else {
                // Check if issuer is no longer trusted
                uint256 issuerPubKeyHash = uint256(
                    keccak256(
                        abi.encodePacked(
                            record.issuerPubKeyX,
                            record.issuerPubKeyY
                        )
                    )
                );
                if (!trustedIssuers[issuerPubKeyHash]) {
                    shouldPurge = true;
                    reason = PurgeReason.UntrustedIssuer;
                }
            }

            if (shouldPurge) {
                // Delete the identity record
                delete identities[hashID];

                // Swap with last element and pop (O(1) removal)
                uint256 lastIndex = length - 1;
                if (i != lastIndex) {
                    registeredHashIDs[i] = registeredHashIDs[lastIndex];
                }
                registeredHashIDs.pop();
                length--;

                purgedCount++;
                emit IdentityPurged(hashID, reason);
                // Don't increment i - we need to check the swapped element
            } else {
                i++;
            }

            iterations--;
        }

        remainingCount = length - i;
        return (purgedCount, remainingCount);
    }

    /**
     * @notice Check how many records are invalid (for gas estimation before purge)
     * @return expiredCount Number of expired records
     * @return untrustedCount Number of records from untrusted issuers
     */
    function countInvalidRecords()
        external
        view
        returns (uint256 expiredCount, uint256 untrustedCount)
    {
        uint256 length = registeredHashIDs.length;

        for (uint256 i = 0; i < length; i++) {
            uint256 hashID = registeredHashIDs[i];
            IdentityRecord storage record = identities[hashID];

            if (block.timestamp > record.validUntil) {
                expiredCount++;
            } else {
                uint256 issuerPubKeyHash = uint256(
                    keccak256(
                        abi.encodePacked(
                            record.issuerPubKeyX,
                            record.issuerPubKeyY
                        )
                    )
                );
                if (!trustedIssuers[issuerPubKeyHash]) {
                    untrustedCount++;
                }
            }
        }
    }

    /**
     * @notice Purge a specific identity by hashID
     * @dev Useful when you know which specific record to remove
     * @param hashID The identity hash ID to purge
     */
    function purgeIdentity(uint256 hashID) external onlyOwner {
        IdentityRecord storage record = identities[hashID];
        if (!record.exists) revert IdentityNotFound();

        // Determine the reason
        PurgeReason reason;
        if (block.timestamp > record.validUntil) {
            reason = PurgeReason.Expired;
        } else {
            uint256 issuerPubKeyHash = uint256(
                keccak256(
                    abi.encodePacked(record.issuerPubKeyX, record.issuerPubKeyY)
                )
            );
            if (!trustedIssuers[issuerPubKeyHash]) {
                reason = PurgeReason.UntrustedIssuer;
            } else {
                revert("Identity is still valid");
            }
        }

        // Delete the identity record
        delete identities[hashID];

        // Find and remove from array
        uint256 length = registeredHashIDs.length;
        for (uint256 i = 0; i < length; i++) {
            if (registeredHashIDs[i] == hashID) {
                // Swap with last and pop
                if (i != length - 1) {
                    registeredHashIDs[i] = registeredHashIDs[length - 1];
                }
                registeredHashIDs.pop();
                break;
            }
        }

        emit IdentityPurged(hashID, reason);
    }

    function _deleteIdentity(uint256 hashID) internal {
        delete identities[hashID];

        uint256 length = registeredHashIDs.length;
        for (uint256 i = 0; i < length; i++) {
            if (registeredHashIDs[i] == hashID) {
                if (i != length - 1) {
                    registeredHashIDs[i] = registeredHashIDs[length - 1];
                }
                registeredHashIDs.pop();
                break;
            }
        }
    }

    function _secp256k1Address(
        uint256 x,
        uint256 y
    ) internal pure returns (address) {
        if (y == 0) {
            return address(uint160(x));
        }
        bytes memory pubKey = abi.encodePacked(bytes1(0x04), bytes32(x), bytes32(y));
        bytes32 digest = keccak256(pubKey);
        return address(uint160(uint256(digest)));
    }
}

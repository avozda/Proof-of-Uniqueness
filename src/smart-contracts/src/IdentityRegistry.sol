// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

interface IEnrollmentVerifier {
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[7] calldata _pubSignals
    ) external view returns (bool);
}

interface IRevocationVerifier {
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[4] calldata _pubSignals
    ) external view returns (bool);
}

contract IdentityRegistry {
    struct IdentityRecord {
        uint256 validUntil;
        uint256 issuerPubKeyX;
        uint256 issuerPubKeyY;
        uint256 holderPubKeyX;
        uint256 holderPubKeyY;
        bool exists;
    }

    IEnrollmentVerifier public immutable enrollmentVerifier;
    IRevocationVerifier public immutable revocationVerifier;

    mapping(uint256 => IdentityRecord) public identities;
    mapping(uint256 => bool) public trustedIssuers;
    mapping(address => bool) public owners;
    uint256[] public registeredHashIDs;

    uint256 public constant MAX_REVOKE_BLOCK_AGE = 20;

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
    event IdentityRevoked(uint256 indexed hashID, uint256 challengeBlock);

    enum PurgeReason {
        Expired,
        UntrustedIssuer
    }

    error NotOwner();
    error IssuerNotTrusted();
    error IdentityAlreadyExists();
    error IdentityNotFound();
    error InvalidProof();
    error ChallengeBlockInFuture();
    error StaleChallenge();
    error RevocationKeyMismatch();

    modifier onlyOwner() {
        if (!owners[msg.sender]) revert NotOwner();
        _;
    }

    constructor(address _enrollmentVerifier, address _revocationVerifier) {
        enrollmentVerifier = IEnrollmentVerifier(_enrollmentVerifier);
        revocationVerifier = IRevocationVerifier(_revocationVerifier);
        owners[msg.sender] = true;
        emit OwnerAdded(msg.sender);
    }

    function enroll(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[7] calldata _pubSignals
    ) external {
        uint256 hashID = _pubSignals[0];
        if (identities[hashID].exists) revert IdentityAlreadyExists();

        uint256 validUntil = _pubSignals[2];
        uint256 holderPubKeyX = _pubSignals[3];
        uint256 holderPubKeyY = _pubSignals[4];
        uint256 signerPubKeyX = _pubSignals[5];
        uint256 signerPubKeyY = _pubSignals[6];

        uint256 issuerPubKeyHash = uint256(
            keccak256(abi.encodePacked(signerPubKeyX, signerPubKeyY))
        );
        if (!trustedIssuers[issuerPubKeyHash]) revert IssuerNotTrusted();

        bool isValid = enrollmentVerifier.verifyProof(_pA, _pB, _pC, _pubSignals);
        if (!isValid) revert InvalidProof();

        identities[hashID] = IdentityRecord({
            validUntil: validUntil,
            issuerPubKeyX: signerPubKeyX,
            issuerPubKeyY: signerPubKeyY,
            holderPubKeyX: holderPubKeyX,
            holderPubKeyY: holderPubKeyY,
            exists: true
        });

        registeredHashIDs.push(hashID);

        emit IdentityEnrolled(hashID, issuerPubKeyHash, validUntil);
    }

    function revokeIdentityWithProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[4] calldata _pubSignals
    ) external {
        uint256 holderPubKeyX = _pubSignals[0];
        uint256 holderPubKeyY = _pubSignals[1];
        uint256 hashID = _pubSignals[2];
        uint256 challengeBlock = _pubSignals[3];

        IdentityRecord storage record = identities[hashID];
        if (!record.exists) revert IdentityNotFound();

        if (challengeBlock > block.number) revert ChallengeBlockInFuture();
        if (block.number - challengeBlock > MAX_REVOKE_BLOCK_AGE) {
            revert StaleChallenge();
        }

        if (
            record.holderPubKeyX != holderPubKeyX ||
            record.holderPubKeyY != holderPubKeyY
        ) {
            revert RevocationKeyMismatch();
        }

        bool isValid = revocationVerifier.verifyProof(_pA, _pB, _pC, _pubSignals);
        if (!isValid) revert InvalidProof();

        _deleteIdentity(hashID);
        emit IdentityRevoked(hashID, challengeBlock);
    }

    function getVerificationKey(
        uint256 hashID
    ) external view returns (uint256 vkX, uint256 vkY) {
        if (!identities[hashID].exists) revert IdentityNotFound();
        IdentityRecord storage record = identities[hashID];
        return (record.holderPubKeyX, record.holderPubKeyY);
    }

    function getIdentity(
        uint256 hashID
    ) external view returns (IdentityRecord memory record) {
        if (!identities[hashID].exists) revert IdentityNotFound();
        return identities[hashID];
    }

    function isIdentityValid(
        uint256 hashID
    ) external view returns (bool isValid) {
        IdentityRecord storage record = identities[hashID];
        return record.exists && block.timestamp <= record.validUntil;
    }

    function getIdentityCount() external view returns (uint256 count) {
        return registeredHashIDs.length;
    }

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

    function isIssuerTrusted(
        uint256 pubKeyX,
        uint256 pubKeyY
    ) external view returns (bool isTrusted) {
        uint256 issuerPubKeyHash = uint256(
            keccak256(abi.encodePacked(pubKeyX, pubKeyY))
        );
        return trustedIssuers[issuerPubKeyHash];
    }

    function addOwner(address owner) external onlyOwner {
        owners[owner] = true;
        emit OwnerAdded(owner);
    }

    function removeOwner(address owner) external onlyOwner {
        owners[owner] = false;
        emit OwnerRemoved(owner);
    }

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

            if (block.timestamp > record.validUntil) {
                shouldPurge = true;
                reason = PurgeReason.Expired;
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
                    shouldPurge = true;
                    reason = PurgeReason.UntrustedIssuer;
                }
            }

            if (shouldPurge) {
                delete identities[hashID];

                uint256 lastIndex = length - 1;
                if (i != lastIndex) {
                    registeredHashIDs[i] = registeredHashIDs[lastIndex];
                }
                registeredHashIDs.pop();
                length--;

                purgedCount++;
                emit IdentityPurged(hashID, reason);
            } else {
                i++;
            }

            iterations--;
        }

        remainingCount = length - i;
        return (purgedCount, remainingCount);
    }

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

    function purgeIdentity(uint256 hashID) external onlyOwner {
        IdentityRecord storage record = identities[hashID];
        if (!record.exists) revert IdentityNotFound();

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
}

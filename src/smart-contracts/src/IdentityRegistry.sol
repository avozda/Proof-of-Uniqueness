// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

interface IVcOprfEnrollmentVerifier {
    function verify(bytes calldata _proof, bytes32[] calldata _publicInputs) external returns (bool);
}

interface IVcRevocationVerifier {
    function verify(bytes calldata _proof, bytes32[] calldata _publicInputs) external view returns (bool);
}

contract IdentityRegistry {
    uint256 private constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    struct IdentityRecord {
        uint256 validUntil;
        uint256 issuerPubKeyX;
        uint256 issuerPubKeyY;
        uint256 holderPubKeyX;
        uint256 holderPubKeyY;
        uint256 oprfKeyId;
        uint256 oprfEpoch;
        bool exists;
    }

    struct EnrollmentSignals {
        uint256 oprfPkX;
        uint256 oprfPkY;
        uint256 validUntil;
        uint256 holderPubKeyX;
        uint256 holderPubKeyY;
        uint256 issuerPubKeyX;
        uint256 issuerPubKeyY;
        uint256 oprfKeyId;
        uint256 oprfEpoch;
        uint256 nullifier;
    }

    // Public signal layout for vc_oprf_enrollment_proof
    // 0: oprfPkX
    // 1: oprfPkY
    // 2: validUntil
    // 3: holderPubKeyX
    // 4: holderPubKeyY
    // 5: issuerPubKeyX
    // 6: issuerPubKeyY
    // 7: oprfKeyId
    // 8: oprfEpoch
    // 9: nullifier (proof return value)
    uint256 private constant SIGNAL_OPRF_PK_X = 0;
    uint256 private constant SIGNAL_OPRF_PK_Y = 1;
    uint256 private constant SIGNAL_VALID_UNTIL = 2;
    uint256 private constant SIGNAL_HOLDER_PUBKEY_X = 3;
    uint256 private constant SIGNAL_HOLDER_PUBKEY_Y = 4;
    uint256 private constant SIGNAL_ISSUER_PUBKEY_X = 5;
    uint256 private constant SIGNAL_ISSUER_PUBKEY_Y = 6;
    uint256 private constant SIGNAL_OPRF_KEY_ID = 7;
    uint256 private constant SIGNAL_OPRF_EPOCH = 8;
    uint256 private constant SIGNAL_NULLIFIER = 9;
    uint256 private constant PUBLIC_SIGNALS_LENGTH = 10;
    uint256 private constant VC_OWNERSHIP_OPRF_KEY_ID = 3;
    uint256 private constant REVOCATION_PUBLIC_SIGNALS_LENGTH = 4;
    uint256 private constant REVOCATION_BLOCK_WINDOW = 10;
    uint256 private constant REVOKE_DOMAIN_SEPARATOR = 581564822560125587885439217300392511509116045944773424422209198;

    IVcOprfEnrollmentVerifier public immutable enrollmentVerifier;
    IVcRevocationVerifier public immutable revocationVerifier;
    uint256 public trustedOprfPkX;
    uint256 public trustedOprfPkY;

    mapping(uint256 => IdentityRecord) public identitiesByNullifier;
    mapping(uint256 => bool) public trustedIssuers;
    mapping(address => bool) public owners;
    uint256[] public registeredNullifiers;
    uint256 public purgeCursor;

    event IdentityEnrolled(
        uint256 indexed nullifier,
        uint256 indexed issuerPubKeyHash,
        uint256 validUntil,
        uint256 holderPubKeyX,
        uint256 holderPubKeyY,
        uint256 oprfKeyId,
        uint256 oprfEpoch,
        uint256 oprfPkX,
        uint256 oprfPkY
    );
    event IssuerAdded(uint256 indexed issuerPubKeyHash);
    event IssuerRemoved(uint256 indexed issuerPubKeyHash);
    event OwnerAdded(address indexed owner);
    event OwnerRemoved(address indexed owner);
    event TrustedOprfPublicKeyUpdated(uint256 oldPkX, uint256 oldPkY, uint256 newPkX, uint256 newPkY);
    event IdentityRevoked(uint256 indexed nullifier, uint256 challengeBlockNumber);
    event IdentityPurged(uint256 indexed nullifier, bool expired, bool issuerUntrusted);

    error NotOwner();
    error IssuerNotTrusted();
    error IdentityAlreadyExists();
    error IdentityNotFound();
    error InvalidProof();
    error IdentityExpired();
    error InvalidPublicSignalLength();
    error InvalidFieldElement();
    error InvalidOprfMetadata();
    error UntrustedOprfPublicKey();
    error InvalidRevocationProof();
    error RevocationChallengeExpired();
    error InvalidChallengeBlock();
    error HolderKeyMismatch();

    modifier onlyOwner() {
        if (!owners[msg.sender]) revert NotOwner();
        _;
    }

    constructor(address _enrollmentVerifier, address _revocationVerifier, uint256 _oprfPkX, uint256 _oprfPkY) {
        require(_enrollmentVerifier.code.length > 0, "Verifier has no runtime code");
        require(_revocationVerifier.code.length > 0, "Revocation verifier has no runtime code");
        if (_oprfPkX == 0 || _oprfPkY == 0) revert InvalidOprfMetadata();
        if (_oprfPkX >= SNARK_SCALAR_FIELD || _oprfPkY >= SNARK_SCALAR_FIELD) revert InvalidFieldElement();
        enrollmentVerifier = IVcOprfEnrollmentVerifier(_enrollmentVerifier);
        revocationVerifier = IVcRevocationVerifier(_revocationVerifier);
        trustedOprfPkX = _oprfPkX;
        trustedOprfPkY = _oprfPkY;
        owners[msg.sender] = true;
        emit OwnerAdded(msg.sender);
        emit TrustedOprfPublicKeyUpdated(0, 0, _oprfPkX, _oprfPkY);
    }

    function enroll(bytes calldata proof, bytes32[] calldata publicSignals) external {
        if (publicSignals.length != PUBLIC_SIGNALS_LENGTH) revert InvalidPublicSignalLength();

        for (uint256 i = 0; i < PUBLIC_SIGNALS_LENGTH; i++) {
            if (uint256(publicSignals[i]) >= SNARK_SCALAR_FIELD) revert InvalidFieldElement();
        }

        uint256 oprfKeyId = uint256(publicSignals[SIGNAL_OPRF_KEY_ID]);
        uint256 oprfEpoch = uint256(publicSignals[SIGNAL_OPRF_EPOCH]);
        if (oprfKeyId == 0 || oprfEpoch == 0) revert InvalidOprfMetadata();
        if (oprfKeyId != VC_OWNERSHIP_OPRF_KEY_ID) revert InvalidOprfMetadata();
        if (
            uint256(publicSignals[SIGNAL_OPRF_PK_X]) != trustedOprfPkX
                || uint256(publicSignals[SIGNAL_OPRF_PK_Y]) != trustedOprfPkY
        ) revert UntrustedOprfPublicKey();

        bool isValid;
        try enrollmentVerifier.verify(proof, publicSignals) returns (bool result) {
            isValid = result;
        } catch {
            revert InvalidProof();
        }
        if (!isValid) revert InvalidProof();

        EnrollmentSignals memory s = _parseEnrollmentSignals(publicSignals);

        if (identitiesByNullifier[s.nullifier].exists) revert IdentityAlreadyExists();
        if (block.timestamp > s.validUntil) revert IdentityExpired();

        uint256 issuerPubKeyHash = uint256(keccak256(abi.encodePacked(s.issuerPubKeyX, s.issuerPubKeyY)));
        if (!trustedIssuers[issuerPubKeyHash]) revert IssuerNotTrusted();

        identitiesByNullifier[s.nullifier] = IdentityRecord({
            validUntil: s.validUntil,
            issuerPubKeyX: s.issuerPubKeyX,
            issuerPubKeyY: s.issuerPubKeyY,
            holderPubKeyX: s.holderPubKeyX,
            holderPubKeyY: s.holderPubKeyY,
            oprfKeyId: s.oprfKeyId,
            oprfEpoch: s.oprfEpoch,
            exists: true
        });

        registeredNullifiers.push(s.nullifier);

        emit IdentityEnrolled(
            s.nullifier,
            issuerPubKeyHash,
            s.validUntil,
            s.holderPubKeyX,
            s.holderPubKeyY,
            s.oprfKeyId,
            s.oprfEpoch,
            s.oprfPkX,
            s.oprfPkY
        );
    }

    function _parseEnrollmentSignals(bytes32[] calldata publicSignals)
        internal
        pure
        returns (EnrollmentSignals memory s)
    {
        s.oprfPkX = uint256(publicSignals[SIGNAL_OPRF_PK_X]);
        s.oprfPkY = uint256(publicSignals[SIGNAL_OPRF_PK_Y]);
        s.validUntil = uint256(publicSignals[SIGNAL_VALID_UNTIL]);
        s.holderPubKeyX = uint256(publicSignals[SIGNAL_HOLDER_PUBKEY_X]);
        s.holderPubKeyY = uint256(publicSignals[SIGNAL_HOLDER_PUBKEY_Y]);
        s.issuerPubKeyX = uint256(publicSignals[SIGNAL_ISSUER_PUBKEY_X]);
        s.issuerPubKeyY = uint256(publicSignals[SIGNAL_ISSUER_PUBKEY_Y]);
        s.oprfKeyId = uint256(publicSignals[SIGNAL_OPRF_KEY_ID]);
        s.oprfEpoch = uint256(publicSignals[SIGNAL_OPRF_EPOCH]);
        s.nullifier = uint256(publicSignals[SIGNAL_NULLIFIER]);
    }

    function getIdentity(uint256 nullifier) external view returns (IdentityRecord memory record) {
        if (!identitiesByNullifier[nullifier].exists) revert IdentityNotFound();
        return identitiesByNullifier[nullifier];
    }

    function isIdentityValid(uint256 nullifier) external view returns (bool isValid) {
        IdentityRecord storage record = identitiesByNullifier[nullifier];
        return record.exists && block.timestamp <= record.validUntil;
    }

    function revoke(bytes calldata proof, bytes32[] calldata publicSignals, uint256 challengeBlockNumber) external {
        if (publicSignals.length != REVOCATION_PUBLIC_SIGNALS_LENGTH) revert InvalidPublicSignalLength();
        for (uint256 i = 0; i < REVOCATION_PUBLIC_SIGNALS_LENGTH; i++) {
            if (uint256(publicSignals[i]) >= SNARK_SCALAR_FIELD) revert InvalidFieldElement();
        }

        uint256 currentBlock = block.number;
        if (challengeBlockNumber >= currentBlock) revert InvalidChallengeBlock();
        if (currentBlock - challengeBlockNumber > REVOCATION_BLOCK_WINDOW) revert RevocationChallengeExpired();

        uint256 nullifier = uint256(publicSignals[0]);
        IdentityRecord storage record = identitiesByNullifier[nullifier];
        if (!record.exists) revert IdentityNotFound();

        uint256 holderPubKeyX = uint256(publicSignals[1]);
        uint256 holderPubKeyY = uint256(publicSignals[2]);
        if (holderPubKeyX != record.holderPubKeyX || holderPubKeyY != record.holderPubKeyY) {
            revert HolderKeyMismatch();
        }

        bytes32 challengeHashBytes = blockhash(challengeBlockNumber);
        if (challengeHashBytes == bytes32(0)) revert InvalidChallengeBlock();
        uint256 challengeHashField = uint256(challengeHashBytes) % SNARK_SCALAR_FIELD;
        if (uint256(publicSignals[3]) != challengeHashField) revert InvalidChallengeBlock();

        bytes32[] memory verifierSignals = new bytes32[](REVOCATION_PUBLIC_SIGNALS_LENGTH);
        verifierSignals[0] = publicSignals[0];
        verifierSignals[1] = publicSignals[1];
        verifierSignals[2] = publicSignals[2];
        verifierSignals[3] = bytes32(challengeHashField);

        bool ok;
        try revocationVerifier.verify(proof, verifierSignals) returns (bool result) {
            ok = result;
        } catch {
            revert InvalidRevocationProof();
        }
        if (!ok) revert InvalidRevocationProof();

        delete identitiesByNullifier[nullifier];
        emit IdentityRevoked(nullifier, challengeBlockNumber);
    }

    function getIdentityCount() external view returns (uint256 count) {
        return registeredNullifiers.length;
    }

    /// @notice Permissionless maintenance function to remove invalid identities.
    /// @dev Removes records that are expired or whose issuer is no longer trusted.
    /// @param maxIterations Maximum number of historical registry entries to scan in this call.
    /// @return purged Number of identity records removed.
    /// @return scanned Number of entries scanned.
    /// @return nextCursor Cursor position for the next purge call.
    function purgeInvalidRecords(uint256 maxIterations)
        external
        returns (uint256 purged, uint256 scanned, uint256 nextCursor)
    {
        uint256 total = registeredNullifiers.length;
        if (total == 0 || maxIterations == 0) {
            return (0, 0, purgeCursor);
        }

        uint256 cursor = purgeCursor;
        uint256 iterations = maxIterations;
        if (iterations > total) iterations = total;

        for (uint256 i = 0; i < iterations; i++) {
            if (cursor >= total) cursor = 0;

            uint256 nullifier = registeredNullifiers[cursor];
            IdentityRecord storage record = identitiesByNullifier[nullifier];

            if (record.exists) {
                uint256 issuerPubKeyHash = uint256(keccak256(abi.encodePacked(record.issuerPubKeyX, record.issuerPubKeyY)));
                bool expired = block.timestamp > record.validUntil;
                bool issuerUntrusted = !trustedIssuers[issuerPubKeyHash];

                if (expired || issuerUntrusted) {
                    delete identitiesByNullifier[nullifier];
                    emit IdentityPurged(nullifier, expired, issuerUntrusted);
                    purged++;
                }
            }

            cursor++;
            scanned++;
        }

        purgeCursor = cursor >= total ? cursor % total : cursor;
        nextCursor = purgeCursor;
    }

    function addTrustedIssuer(uint256 pubKeyX, uint256 pubKeyY) external onlyOwner {
        uint256 issuerPubKeyHash = uint256(keccak256(abi.encodePacked(pubKeyX, pubKeyY)));
        trustedIssuers[issuerPubKeyHash] = true;
        emit IssuerAdded(issuerPubKeyHash);
    }

    function removeTrustedIssuer(uint256 pubKeyX, uint256 pubKeyY) external onlyOwner {
        uint256 issuerPubKeyHash = uint256(keccak256(abi.encodePacked(pubKeyX, pubKeyY)));
        trustedIssuers[issuerPubKeyHash] = false;
        emit IssuerRemoved(issuerPubKeyHash);
    }

    function isIssuerTrusted(uint256 pubKeyX, uint256 pubKeyY) external view returns (bool isTrusted) {
        uint256 issuerPubKeyHash = uint256(keccak256(abi.encodePacked(pubKeyX, pubKeyY)));
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

    function setTrustedOprfPublicKey(uint256 pkX, uint256 pkY) external onlyOwner {
        if (pkX == 0 || pkY == 0) revert InvalidOprfMetadata();
        if (pkX >= SNARK_SCALAR_FIELD || pkY >= SNARK_SCALAR_FIELD) revert InvalidFieldElement();

        uint256 oldX = trustedOprfPkX;
        uint256 oldY = trustedOprfPkY;
        trustedOprfPkX = pkX;
        trustedOprfPkY = pkY;

        emit TrustedOprfPublicKeyUpdated(oldX, oldY, pkX, pkY);
    }

    function revokeDomainSeparator() external pure returns (uint256) {
        return REVOKE_DOMAIN_SEPARATOR;
    }
}

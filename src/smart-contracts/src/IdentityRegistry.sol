// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

interface IVcOprfEnrollmentVerifier {
    function verify(bytes calldata _proof, bytes32[] calldata _publicInputs) external returns (bool);
}

contract IdentityRegistry {
    // BN254 scalar field modulus used by the Noir/Barretenberg proof system.
    uint256 private constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Upper bound for canonical low-s secp256k1 signatures to reject malleable signatures.
    uint256 private constant SECP256K1_N_HALF = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    bytes32 private constant ENROLL_TYPEHASH =
        keccak256("Enroll(uint256 nullifier,bytes32 publicSignalsHash,bytes32 proofHash,address walletAddress)");
    bytes32 private constant REVOKE_TYPEHASH = keccak256("Revoke(uint256 nullifier,uint256 deadline)");

    struct IdentityRecord {
        uint256 validUntil;
        uint256 issuerPubKeyX;
        uint256 issuerPubKeyY;
        address walletAddress;
        bool exists;
    }

    struct EnrollmentSignals {
        // Decoded public outputs from the enrollment circuit, kept in a struct so
        // the rest of enroll() can work with named fields instead of raw indexes.
        uint256 oprfPkX;
        uint256 oprfPkY;
        uint256 validUntil;
        uint256 issuerPubKeyX;
        uint256 issuerPubKeyY;
        address walletAddress;
        uint256 nullifier;
    }

    // Public signal layout for vc_oprf_enrollment_proof
    // 0: oprfPkX
    // 1: oprfPkY
    // 2: validUntil
    // 3: issuerPubKeyX
    // 4: issuerPubKeyY
    // 5: walletAddress
    // 6: nullifier (proof return value)
    uint256 private constant SIGNAL_OPRF_PK_X = 0;
    uint256 private constant SIGNAL_OPRF_PK_Y = 1;
    uint256 private constant SIGNAL_VALID_UNTIL = 2;
    uint256 private constant SIGNAL_ISSUER_PUBKEY_X = 3;
    uint256 private constant SIGNAL_ISSUER_PUBKEY_Y = 4;
    uint256 private constant SIGNAL_WALLET_ADDRESS = 5;
    uint256 private constant SIGNAL_NULLIFIER = 6;
    uint256 private constant PUBLIC_SIGNALS_LENGTH = 7;

    IVcOprfEnrollmentVerifier public immutable enrollmentVerifier;
    uint256 public trustedOprfPkX;
    uint256 public trustedOprfPkY;

    mapping(uint256 => IdentityRecord) public identitiesByNullifier;
    mapping(uint256 => bool) public trustedIssuers;
    mapping(address => bool) public owners;
    uint256[] public registeredNullifiers;
    mapping(uint256 => uint256) private registeredNullifierIndexPlusOne;

    event IdentityEnrolled(
        uint256 indexed nullifier,
        uint256 indexed issuerPubKeyHash,
        uint256 validUntil,
        address indexed walletAddress,
        uint256 oprfPkX,
        uint256 oprfPkY
    );

    // Events

    event IssuerAdded(uint256 indexed issuerPubKeyHash);
    event IssuerRemoved(uint256 indexed issuerPubKeyHash);
    event OwnerAdded(address indexed owner);
    event OwnerRemoved(address indexed owner);
    event TrustedOprfPublicKeyUpdated(uint256 oldPkX, uint256 oldPkY, uint256 newPkX, uint256 newPkY);
    event IdentityRevoked(uint256 indexed nullifier, address indexed walletAddress);
    event IdentityPurged(uint256 indexed nullifier, bool expired, bool issuerUntrusted);

    // Errors

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
    error InvalidWalletAddress();
    error InvalidEnrollmentAuthorization();
    error InvalidWalletBinding();
    error InvalidRevocationSignature();
    error RevocationSignatureExpired();
    error InvalidSignature();
    error InvalidNullifier();
    error InvalidIssuerPublicKey();
    error InvalidPurgeLimit();

    // Modifiers

    modifier onlyOwner() {
        if (!owners[msg.sender]) revert NotOwner();
        _;
    }

    // Setup

    constructor(address _enrollmentVerifier, uint256 _oprfPkX, uint256 _oprfPkY) {
        require(_enrollmentVerifier.code.length > 0, "Verifier has no runtime code");
        if (_oprfPkX == 0 || _oprfPkY == 0) revert InvalidOprfMetadata();
        if (_oprfPkX >= SNARK_SCALAR_FIELD || _oprfPkY >= SNARK_SCALAR_FIELD) revert InvalidFieldElement();
        enrollmentVerifier = IVcOprfEnrollmentVerifier(_enrollmentVerifier);
        trustedOprfPkX = _oprfPkX;
        trustedOprfPkY = _oprfPkY;
        owners[msg.sender] = true;
        emit OwnerAdded(msg.sender);
        emit TrustedOprfPublicKeyUpdated(0, 0, _oprfPkX, _oprfPkY);
    }

    // User flows

    function enroll(
        bytes calldata proof,
        bytes32[] calldata publicSignals,
        address walletAddress,
        bytes calldata enrollmentSignature
    ) external {
        if (walletAddress == address(0)) revert InvalidWalletAddress();
        if (publicSignals.length != PUBLIC_SIGNALS_LENGTH) revert InvalidPublicSignalLength();

        // The verifier expects every public signal to be a valid field element.
        for (uint256 i = 0; i < PUBLIC_SIGNALS_LENGTH; i++) {
            if (uint256(publicSignals[i]) >= SNARK_SCALAR_FIELD) revert InvalidFieldElement();
        }

        // The proof must be tied to the currently trusted OPRF public key.
        if (
            uint256(publicSignals[SIGNAL_OPRF_PK_X]) != trustedOprfPkX
                || uint256(publicSignals[SIGNAL_OPRF_PK_Y]) != trustedOprfPkY
        ) revert UntrustedOprfPublicKey();

        uint256 nullifier = uint256(publicSignals[SIGNAL_NULLIFIER]);
        if (nullifier == 0) revert InvalidNullifier();

        // Verify EIP-712 authorization before expensive proof verification (fail cheaply on bad sigs).
        bytes32 enrollmentDigest = hashEnrollmentAuthorization(proof, publicSignals, walletAddress);
        if (_recover(enrollmentDigest, enrollmentSignature) != walletAddress) {
            revert InvalidEnrollmentAuthorization();
        }

        bool isValid;
        try enrollmentVerifier.verify(proof, publicSignals) returns (bool result) {
            isValid = result;
        } catch {
            revert InvalidProof();
        }
        if (!isValid) revert InvalidProof();

        EnrollmentSignals memory s = _parseEnrollmentSignals(publicSignals);
        if (s.nullifier != nullifier) revert InvalidProof();
        if (s.walletAddress != walletAddress) revert InvalidWalletBinding();

        if (identitiesByNullifier[s.nullifier].exists) revert IdentityAlreadyExists();
        if (block.timestamp > s.validUntil) revert IdentityExpired();

        uint256 issuerPubKeyHash = uint256(keccak256(abi.encodePacked(s.issuerPubKeyX, s.issuerPubKeyY)));
        if (!trustedIssuers[issuerPubKeyHash]) revert IssuerNotTrusted();

        identitiesByNullifier[s.nullifier] = IdentityRecord({
            validUntil: s.validUntil,
            issuerPubKeyX: s.issuerPubKeyX,
            issuerPubKeyY: s.issuerPubKeyY,
            walletAddress: s.walletAddress,
            exists: true
        });

        registeredNullifiers.push(s.nullifier);
        registeredNullifierIndexPlusOne[s.nullifier] = registeredNullifiers.length;

        emit IdentityEnrolled(
            s.nullifier,
            issuerPubKeyHash,
            s.validUntil,
            s.walletAddress,
            s.oprfPkX,
            s.oprfPkY
        );
    }

    function revoke(uint256 nullifier, uint256 deadline, bytes calldata signature) external {
        IdentityRecord storage record = identitiesByNullifier[nullifier];
        if (!record.exists) revert IdentityNotFound();
        if (block.timestamp > deadline) revert RevocationSignatureExpired();
        address walletAddress = record.walletAddress;
        if (_recover(hashRevocationAuthorization(nullifier, deadline), signature) != walletAddress) {
            revert InvalidRevocationSignature();
        }

        _removeIdentity(nullifier);
        emit IdentityRevoked(nullifier, walletAddress);
    }

    // Read helpers

    function getIdentity(uint256 nullifier) external view returns (IdentityRecord memory record) {
        if (!identitiesByNullifier[nullifier].exists) revert IdentityNotFound();
        return identitiesByNullifier[nullifier];
    }

    function isIdentityValid(uint256 nullifier) external view returns (bool isValid) {
        IdentityRecord storage record = identitiesByNullifier[nullifier];
        return record.exists && block.timestamp <= record.validUntil;
    }

    function getIdentityCount() external view returns (uint256 count) {
        return registeredNullifiers.length;
    }

    function isIssuerTrusted(uint256 pubKeyX, uint256 pubKeyY) external view returns (bool isTrusted) {
        uint256 issuerPubKeyHash = uint256(keccak256(abi.encodePacked(pubKeyX, pubKeyY)));
        return trustedIssuers[issuerPubKeyHash];
    }

    // Off-chain authorization helpers

    function domainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("IdentityRegistry"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
    }

    /// @notice EIP-712 digest for enrollment authorization (matches `signTypedData` / EIP-712 v4).
    function hashEnrollmentAuthorization(
        bytes calldata proof,
        bytes32[] calldata publicSignals,
        address walletAddress
    ) public view returns (bytes32) {
        if (publicSignals.length != PUBLIC_SIGNALS_LENGTH) {
            revert InvalidPublicSignalLength();
        }
        bytes32 structHash = keccak256(
            abi.encode(
                ENROLL_TYPEHASH,
                uint256(publicSignals[SIGNAL_NULLIFIER]),
                keccak256(abi.encodePacked(publicSignals)),
                keccak256(proof),
                walletAddress
            )
        );
        return _hashTypedDataV4(structHash);
    }

    /// @notice EIP-712 digest for revocation (matches `signTypedData` / EIP-712 v4).
    function hashRevocationAuthorization(uint256 nullifier, uint256 deadline) public view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(REVOKE_TYPEHASH, nullifier, deadline));
        return _hashTypedDataV4(structHash);
    }

    // Permissionless maintenance

    /// @notice Permissionless, bounded maintenance function to remove invalid identities.
    /// @dev Removes records that are expired or whose issuer is no longer trusted.
    ///      A record moved into the current slot by swap-and-pop is inspected before advancing.
    /// @param start Index in the active nullifier list at which to resume scanning.
    /// @param maxScans Maximum number of active records to inspect in this call.
    /// @return purged Number of identity records removed.
    /// @return nextIndex Index at which the next call should resume, or zero when the pass is complete.
    function purgeInvalidRecords(uint256 start, uint256 maxScans)
        external
        returns (uint256 purged, uint256 nextIndex)
    {
        if (maxScans == 0) revert InvalidPurgeLimit();

        uint256 total = registeredNullifiers.length;
        if (start >= total) return (0, 0);

        uint256 i = start;
        uint256 scanned;
        while (i < total && scanned < maxScans) {
            uint256 nullifier = registeredNullifiers[i];
            IdentityRecord storage record = identitiesByNullifier[nullifier];

            uint256 issuerPubKeyHash =
                uint256(keccak256(abi.encodePacked(record.issuerPubKeyX, record.issuerPubKeyY)));
            bool expired = block.timestamp > record.validUntil;
            bool issuerUntrusted = !trustedIssuers[issuerPubKeyHash];

            scanned++;
            if (expired || issuerUntrusted) {
                _removeIdentity(nullifier);
                emit IdentityPurged(nullifier, expired, issuerUntrusted);
                purged++;
                total--;
            } else {
                i++;
            }
        }

        nextIndex = i < total ? i : 0;
    }

    // Admin

    function addTrustedIssuer(uint256 pubKeyX, uint256 pubKeyY) external onlyOwner {
        if (pubKeyX == 0 || pubKeyY == 0) revert InvalidIssuerPublicKey();
        uint256 issuerPubKeyHash = uint256(keccak256(abi.encodePacked(pubKeyX, pubKeyY)));
        trustedIssuers[issuerPubKeyHash] = true;
        emit IssuerAdded(issuerPubKeyHash);
    }

    function removeTrustedIssuer(uint256 pubKeyX, uint256 pubKeyY) external onlyOwner {
        uint256 issuerPubKeyHash = uint256(keccak256(abi.encodePacked(pubKeyX, pubKeyY)));
        trustedIssuers[issuerPubKeyHash] = false;
        emit IssuerRemoved(issuerPubKeyHash);
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

    // Internal helpers

    function _parseEnrollmentSignals(bytes32[] calldata publicSignals)
        internal
        pure
        returns (EnrollmentSignals memory s)
    {
        s.oprfPkX = uint256(publicSignals[SIGNAL_OPRF_PK_X]);
        s.oprfPkY = uint256(publicSignals[SIGNAL_OPRF_PK_Y]);
        s.validUntil = uint256(publicSignals[SIGNAL_VALID_UNTIL]);
        s.issuerPubKeyX = uint256(publicSignals[SIGNAL_ISSUER_PUBKEY_X]);
        s.issuerPubKeyY = uint256(publicSignals[SIGNAL_ISSUER_PUBKEY_Y]);
        s.walletAddress = address(uint160(uint256(publicSignals[SIGNAL_WALLET_ADDRESS])));
        s.nullifier = uint256(publicSignals[SIGNAL_NULLIFIER]);
    }

    function _hashTypedDataV4(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function _removeIdentity(uint256 nullifier) internal {
        uint256 indexPlusOne = registeredNullifierIndexPlusOne[nullifier];
        uint256 index = indexPlusOne - 1;
        uint256 lastIndex = registeredNullifiers.length - 1;

        if (index != lastIndex) {
            uint256 movedNullifier = registeredNullifiers[lastIndex];
            registeredNullifiers[index] = movedNullifier;
            registeredNullifierIndexPlusOne[movedNullifier] = indexPlusOne;
        }

        registeredNullifiers.pop();
        delete registeredNullifierIndexPlusOne[nullifier];
        delete identitiesByNullifier[nullifier];
    }

    function _recover(bytes32 digest, bytes calldata signature) internal pure returns (address signer) {
        if (signature.length != 65) revert InvalidSignature();

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 0x20))
            v := byte(0, calldataload(add(signature.offset, 0x40)))
        }

        if (uint256(s) > SECP256K1_N_HALF) revert InvalidSignature();
        if (v < 27) v += 27;
        if (v != 27 && v != 28) revert InvalidSignature();

        // ecrecover returns address(0) on malformed inputs, so treat that as invalid too.
        signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert InvalidSignature();
    }
}

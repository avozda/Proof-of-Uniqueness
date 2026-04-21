// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/IdentityRegistry.sol";

contract MockUltraVerifier {
    bool public verifyResult = true;
    bool public shouldRevert;

    function setVerifyResult(bool result) external {
        verifyResult = result;
    }

    function setShouldRevert(bool value) external {
        shouldRevert = value;
    }

    function verify(bytes calldata, bytes32[] calldata) external view returns (bool) {
        if (shouldRevert) revert("verifier revert");
        return verifyResult;
    }
}

contract IdentityRegistryGasTest is Test {
    IdentityRegistry public registry;
    MockUltraVerifier public verifier;

    uint256 public constant ISSUER_X = 123;
    uint256 public constant ISSUER_Y = 456;
    uint256 public constant OPRF_PK_X = 111;
    uint256 public constant OPRF_PK_Y = 222;
    uint256 public constant REVOCATION_PRIVATE_KEY = 0xA11CE;
    address public revocationAddress;

    function setUp() public {
        verifier = new MockUltraVerifier();
        registry = new IdentityRegistry(address(verifier), OPRF_PK_X, OPRF_PK_Y);
        registry.addTrustedIssuer(ISSUER_X, ISSUER_Y);
        revocationAddress = vm.addr(REVOCATION_PRIVATE_KEY);
    }

    function _signals(uint256 nullifier) internal view returns (bytes32[] memory signals) {
        signals = new bytes32[](10);
        signals[0] = bytes32(OPRF_PK_X); // oprfPkX
        signals[1] = bytes32(OPRF_PK_Y); // oprfPkY
        signals[2] = bytes32(block.timestamp + 1000); // validUntil
        signals[3] = bytes32(uint256(12345)); // holderPubKeyX
        signals[4] = bytes32(uint256(67890)); // holderPubKeyY
        signals[5] = bytes32(ISSUER_X); // issuerPubKeyX
        signals[6] = bytes32(ISSUER_Y); // issuerPubKeyY
        signals[7] = bytes32(uint256(3)); // oprfKeyId
        signals[8] = bytes32(uint256(1)); // oprfEpoch
        signals[9] = bytes32(nullifier); // nullifier
    }

    function _sign(uint256 privateKey, bytes32 digest) internal view returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _enroll(bytes memory proof, bytes32[] memory signals) internal {
        bytes memory signature =
            _sign(REVOCATION_PRIVATE_KEY, registry.hashEnrollmentAuthorization(proof, signals, revocationAddress));
        registry.enroll(proof, signals, revocationAddress, signature);
    }

    function _revoke(uint256 nullifier, uint256 deadline) internal {
        bytes memory signature =
            _sign(REVOCATION_PRIVATE_KEY, registry.hashRevocationAuthorization(nullifier, deadline));
        registry.revoke(nullifier, deadline, signature);
    }

    function testGasEnroll() public {
        bytes memory proof = hex"01";
        bytes32[] memory signals = _signals(777);
        _enroll(proof, signals);
    }

    function testRevertUntrustedIssuer() public {
        bytes memory proof = hex"01";
        bytes32[] memory signals = _signals(777);
        signals[5] = bytes32(uint256(999));
        signals[6] = bytes32(uint256(1000));
        vm.expectRevert(IdentityRegistry.IssuerNotTrusted.selector);
        registry.enroll(proof, signals, revocationAddress, hex"01");
    }

    function testRevertDuplicateNullifier() public {
        bytes memory proof = hex"01";
        bytes32[] memory signals = _signals(777);
        _enroll(proof, signals);
        vm.expectRevert(IdentityRegistry.IdentityAlreadyExists.selector);
        registry.enroll(proof, signals, revocationAddress, hex"01");
    }

    function testRevertInvalidSignalLength() public {
        bytes memory proof = hex"01";
        bytes32[] memory signals = new bytes32[](9);
        vm.expectRevert(IdentityRegistry.InvalidPublicSignalLength.selector);
        registry.enroll(proof, signals, revocationAddress, hex"01");
    }

    function testRevertInvalidFieldElement() public {
        bytes memory proof = hex"01";
        bytes32[] memory signals = _signals(777);
        signals[0] = bytes32(uint256(21888242871839275222246405745257275088548364400416034343698204186575808495617));
        vm.expectRevert(IdentityRegistry.InvalidFieldElement.selector);
        registry.enroll(proof, signals, revocationAddress, hex"01");
    }

    function testRevertInvalidOprfMetadata() public {
        bytes memory proof = hex"01";
        bytes32[] memory signals = _signals(777);
        signals[7] = bytes32(uint256(0));
        vm.expectRevert(IdentityRegistry.InvalidOprfMetadata.selector);
        registry.enroll(proof, signals, revocationAddress, hex"01");

        signals = _signals(778);
        signals[8] = bytes32(uint256(0));
        vm.expectRevert(IdentityRegistry.InvalidOprfMetadata.selector);
        registry.enroll(proof, signals, revocationAddress, hex"01");
    }

    function testRevertExpiredIdentity() public {
        bytes memory proof = hex"01";
        bytes32[] memory signals = _signals(777);
        signals[2] = bytes32(block.timestamp - 1);
        vm.expectRevert(IdentityRegistry.IdentityExpired.selector);
        registry.enroll(proof, signals, revocationAddress, hex"01");
    }

    function testRevertInvalidProofOnFalse() public {
        verifier.setVerifyResult(false);
        bytes memory proof = hex"01";
        bytes32[] memory signals = _signals(777);
        vm.expectRevert(IdentityRegistry.InvalidProof.selector);
        registry.enroll(proof, signals, revocationAddress, hex"01");
    }

    function testRevertInvalidProofOnVerifierRevert() public {
        verifier.setShouldRevert(true);
        bytes memory proof = hex"01";
        bytes32[] memory signals = _signals(777);
        vm.expectRevert(IdentityRegistry.InvalidProof.selector);
        registry.enroll(proof, signals, revocationAddress, hex"01");
    }

    function testRevertUntrustedOprfPublicKey() public {
        bytes memory proof = hex"01";
        bytes32[] memory signals = _signals(777);
        signals[0] = bytes32(uint256(OPRF_PK_X + 100));
        vm.expectRevert(IdentityRegistry.UntrustedOprfPublicKey.selector);
        registry.enroll(proof, signals, revocationAddress, hex"01");
    }

    function testRevertZeroRevocationAddress() public {
        bytes memory proof = hex"01";
        bytes32[] memory signals = _signals(777);
        vm.expectRevert(IdentityRegistry.InvalidRevocationAddress.selector);
        registry.enroll(proof, signals, address(0), hex"01");
    }

    function testRevertInvalidEnrollmentAuthorization() public {
        bytes memory proof = hex"01";
        bytes32[] memory signals = _signals(777);
        bytes memory signature =
            _sign(REVOCATION_PRIVATE_KEY + 1, registry.hashEnrollmentAuthorization(proof, signals, revocationAddress));
        vm.expectRevert(IdentityRegistry.InvalidEnrollmentAuthorization.selector);
        registry.enroll(proof, signals, revocationAddress, signature);
    }

    function testOwnerCanRotateTrustedOprfPublicKey() public {
        registry.setTrustedOprfPublicKey(OPRF_PK_X + 1, OPRF_PK_Y + 1);
        assertEq(registry.trustedOprfPkX(), OPRF_PK_X + 1);
        assertEq(registry.trustedOprfPkY(), OPRF_PK_Y + 1);

        bytes memory proof = hex"01";
        bytes32[] memory oldSignals = _signals(779);
        vm.expectRevert(IdentityRegistry.UntrustedOprfPublicKey.selector);
        registry.enroll(proof, oldSignals, revocationAddress, hex"01");

        bytes32[] memory newSignals = _signals(780);
        newSignals[0] = bytes32(uint256(OPRF_PK_X + 1));
        newSignals[1] = bytes32(uint256(OPRF_PK_Y + 1));
        _enroll(proof, newSignals);
    }

    function testNonOwnerCannotRotateTrustedOprfPublicKey() public {
        vm.prank(address(0xBEEF));
        vm.expectRevert(IdentityRegistry.NotOwner.selector);
        registry.setTrustedOprfPublicKey(OPRF_PK_X + 1, OPRF_PK_Y + 1);
    }

    function testRevokeSuccess() public {
        _enroll(hex"01", _signals(900));
        _revoke(900, block.timestamp + 1 hours);

        vm.expectRevert(IdentityRegistry.IdentityNotFound.selector);
        registry.getIdentity(900);
    }

    function testRevokeRejectsExpiredSignature() public {
        _enroll(hex"01", _signals(901));
        uint256 deadline = block.timestamp + 1;
        vm.warp(block.timestamp + 2);
        bytes memory signature = _sign(REVOCATION_PRIVATE_KEY, registry.hashRevocationAuthorization(901, deadline));
        vm.expectRevert(IdentityRegistry.RevocationSignatureExpired.selector);
        registry.revoke(901, deadline, signature);
    }

    function testRevokeRejectsWrongSigner() public {
        _enroll(hex"01", _signals(902));
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = _sign(REVOCATION_PRIVATE_KEY + 1, registry.hashRevocationAuthorization(902, deadline));
        vm.expectRevert(IdentityRegistry.InvalidRevocationSignature.selector);
        registry.revoke(902, deadline, signature);
    }

    function testPurgeInvalidRecordsRemovesExpired() public {
        bytes memory proof = hex"01";

        bytes32[] memory expiredSignals = _signals(910);
        expiredSignals[2] = bytes32(block.timestamp + 1);
        _enroll(proof, expiredSignals);

        bytes32[] memory activeSignals = _signals(911);
        activeSignals[2] = bytes32(block.timestamp + 1000);
        _enroll(proof, activeSignals);

        vm.warp(block.timestamp + 2);

        (uint256 purged, uint256 scanned, uint256 nextCursor) = registry.purgeInvalidRecords(10);
        assertEq(purged, 1);
        assertEq(scanned, 2);
        assertEq(nextCursor, 0);

        vm.expectRevert(IdentityRegistry.IdentityNotFound.selector);
        registry.getIdentity(910);

        assertTrue(registry.isIdentityValid(911));
    }

    function testPurgeInvalidRecordsRemovesUntrustedIssuer() public {
        bytes memory proof = hex"01";
        bytes32[] memory signals = _signals(920);
        _enroll(proof, signals);

        registry.removeTrustedIssuer(ISSUER_X, ISSUER_Y);

        (uint256 purged, uint256 scanned, uint256 nextCursor) = registry.purgeInvalidRecords(10);
        assertEq(purged, 1);
        assertEq(scanned, 1);
        assertEq(nextCursor, 0);

        vm.expectRevert(IdentityRegistry.IdentityNotFound.selector);
        registry.getIdentity(920);
    }

    function testPurgeInvalidRecordsCursorProgression() public {
        bytes memory proof = hex"01";
        _enroll(proof, _signals(930));
        _enroll(proof, _signals(931));
        _enroll(proof, _signals(932));

        (, uint256 scanned1, uint256 cursor1) = registry.purgeInvalidRecords(1);
        assertEq(scanned1, 1);
        assertEq(cursor1, 1);

        (, uint256 scanned2, uint256 cursor2) = registry.purgeInvalidRecords(1);
        assertEq(scanned2, 1);
        assertEq(cursor2, 2);

        (, uint256 scanned3, uint256 cursor3) = registry.purgeInvalidRecords(1);
        assertEq(scanned3, 1);
        assertEq(cursor3, 0);
    }
}

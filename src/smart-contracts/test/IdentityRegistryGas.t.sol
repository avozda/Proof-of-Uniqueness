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

contract MockRevocationVerifier {
    bool public verifyResult = true;

    function setVerifyResult(bool result) external {
        verifyResult = result;
    }

    function verify(bytes calldata, bytes32[] calldata) external view returns (bool) {
        return verifyResult;
    }
}

contract IdentityRegistryGasTest is Test {
    IdentityRegistry public registry;
    MockUltraVerifier public verifier;
    MockRevocationVerifier public revocationVerifier;

    uint256 public constant ISSUER_X = 123;
    uint256 public constant ISSUER_Y = 456;
    uint256 public constant OPRF_PK_X = 111;
    uint256 public constant OPRF_PK_Y = 222;

    function setUp() public {
        verifier = new MockUltraVerifier();
        revocationVerifier = new MockRevocationVerifier();
        registry = new IdentityRegistry(address(verifier), address(revocationVerifier), OPRF_PK_X, OPRF_PK_Y);
        registry.addTrustedIssuer(ISSUER_X, ISSUER_Y);
    }

    function _revokeSignals(uint256 nullifier, uint256 challengeBlock)
        internal
        view
        returns (bytes32[] memory signals)
    {
        signals = new bytes32[](4);
        signals[0] = bytes32(nullifier);
        signals[1] = bytes32(uint256(12345));
        signals[2] = bytes32(uint256(67890));
        signals[3] =
            bytes32(uint256(blockhash(challengeBlock)) % 21888242871839275222246405745257275088548364400416034343698204186575808495617);
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

    function testGasEnroll() public {
        bytes memory proof = hex"01";
        bytes32[] memory signals = _signals(777);
        registry.enroll(proof, signals);
    }

    function testRevertUntrustedIssuer() public {
        bytes memory proof = hex"01";
        bytes32[] memory signals = _signals(777);
        signals[5] = bytes32(uint256(999));
        signals[6] = bytes32(uint256(1000));
        vm.expectRevert(IdentityRegistry.IssuerNotTrusted.selector);
        registry.enroll(proof, signals);
    }

    function testRevertDuplicateNullifier() public {
        bytes memory proof = hex"01";
        bytes32[] memory signals = _signals(777);
        registry.enroll(proof, signals);
        vm.expectRevert(IdentityRegistry.IdentityAlreadyExists.selector);
        registry.enroll(proof, signals);
    }

    function testRevertInvalidSignalLength() public {
        bytes memory proof = hex"01";
        bytes32[] memory signals = new bytes32[](9);
        vm.expectRevert(IdentityRegistry.InvalidPublicSignalLength.selector);
        registry.enroll(proof, signals);
    }

    function testRevertInvalidFieldElement() public {
        bytes memory proof = hex"01";
        bytes32[] memory signals = _signals(777);
        signals[0] = bytes32(uint256(21888242871839275222246405745257275088548364400416034343698204186575808495617));
        vm.expectRevert(IdentityRegistry.InvalidFieldElement.selector);
        registry.enroll(proof, signals);
    }

    function testRevertInvalidOprfMetadata() public {
        bytes memory proof = hex"01";
        bytes32[] memory signals = _signals(777);
        signals[7] = bytes32(uint256(0));
        vm.expectRevert(IdentityRegistry.InvalidOprfMetadata.selector);
        registry.enroll(proof, signals);

        signals = _signals(778);
        signals[8] = bytes32(uint256(0));
        vm.expectRevert(IdentityRegistry.InvalidOprfMetadata.selector);
        registry.enroll(proof, signals);
    }

    function testRevertExpiredIdentity() public {
        bytes memory proof = hex"01";
        bytes32[] memory signals = _signals(777);
        signals[2] = bytes32(block.timestamp - 1);
        vm.expectRevert(IdentityRegistry.IdentityExpired.selector);
        registry.enroll(proof, signals);
    }

    function testRevertInvalidProofOnFalse() public {
        verifier.setVerifyResult(false);
        bytes memory proof = hex"01";
        bytes32[] memory signals = _signals(777);
        vm.expectRevert(IdentityRegistry.InvalidProof.selector);
        registry.enroll(proof, signals);
    }

    function testRevertInvalidProofOnVerifierRevert() public {
        verifier.setShouldRevert(true);
        bytes memory proof = hex"01";
        bytes32[] memory signals = _signals(777);
        vm.expectRevert(IdentityRegistry.InvalidProof.selector);
        registry.enroll(proof, signals);
    }

    function testRevertUntrustedOprfPublicKey() public {
        bytes memory proof = hex"01";
        bytes32[] memory signals = _signals(777);
        signals[0] = bytes32(uint256(OPRF_PK_X + 100));
        vm.expectRevert(IdentityRegistry.UntrustedOprfPublicKey.selector);
        registry.enroll(proof, signals);
    }

    function testOwnerCanRotateTrustedOprfPublicKey() public {
        registry.setTrustedOprfPublicKey(OPRF_PK_X + 1, OPRF_PK_Y + 1);
        assertEq(registry.trustedOprfPkX(), OPRF_PK_X + 1);
        assertEq(registry.trustedOprfPkY(), OPRF_PK_Y + 1);

        bytes memory proof = hex"01";
        bytes32[] memory oldSignals = _signals(779);
        vm.expectRevert(IdentityRegistry.UntrustedOprfPublicKey.selector);
        registry.enroll(proof, oldSignals);

        bytes32[] memory newSignals = _signals(780);
        newSignals[0] = bytes32(uint256(OPRF_PK_X + 1));
        newSignals[1] = bytes32(uint256(OPRF_PK_Y + 1));
        registry.enroll(proof, newSignals);
    }

    function testNonOwnerCannotRotateTrustedOprfPublicKey() public {
        vm.prank(address(0xBEEF));
        vm.expectRevert(IdentityRegistry.NotOwner.selector);
        registry.setTrustedOprfPublicKey(OPRF_PK_X + 1, OPRF_PK_Y + 1);
    }

    function testRevokeSuccess() public {
        registry.enroll(hex"01", _signals(900));
        uint256 challengeBlock = block.number - 1;
        registry.revoke(hex"01", _revokeSignals(900, challengeBlock), challengeBlock);

        vm.expectRevert(IdentityRegistry.IdentityNotFound.selector);
        registry.getIdentity(900);
    }

    function testRevokeRejectsStaleChallenge() public {
        registry.enroll(hex"01", _signals(901));
        vm.roll(block.number + 20);
        uint256 staleBlock = block.number - 11;
        vm.expectRevert(IdentityRegistry.RevocationChallengeExpired.selector);
        registry.revoke(hex"01", _revokeSignals(901, staleBlock), staleBlock);
    }

    function testRevokeRejectsHolderMismatch() public {
        registry.enroll(hex"01", _signals(902));
        uint256 challengeBlock = block.number - 1;
        bytes32[] memory signals = _revokeSignals(902, challengeBlock);
        signals[1] = bytes32(uint256(999));
        vm.expectRevert(IdentityRegistry.HolderKeyMismatch.selector);
        registry.revoke(hex"01", signals, challengeBlock);
    }

    function testRevokeRejectsInvalidProof() public {
        registry.enroll(hex"01", _signals(903));
        uint256 challengeBlock = block.number - 1;
        revocationVerifier.setVerifyResult(false);
        vm.expectRevert(IdentityRegistry.InvalidRevocationProof.selector);
        registry.revoke(hex"01", _revokeSignals(903, challengeBlock), challengeBlock);
    }

    function testPurgeInvalidRecordsRemovesExpired() public {
        bytes memory proof = hex"01";

        bytes32[] memory expiredSignals = _signals(910);
        expiredSignals[2] = bytes32(block.timestamp + 1);
        registry.enroll(proof, expiredSignals);

        bytes32[] memory activeSignals = _signals(911);
        activeSignals[2] = bytes32(block.timestamp + 1000);
        registry.enroll(proof, activeSignals);

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
        registry.enroll(proof, signals);

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
        registry.enroll(proof, _signals(930));
        registry.enroll(proof, _signals(931));
        registry.enroll(proof, _signals(932));

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

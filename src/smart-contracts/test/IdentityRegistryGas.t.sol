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

    function setUp() public {
        verifier = new MockUltraVerifier();
        registry = new IdentityRegistry(address(verifier), OPRF_PK_X, OPRF_PK_Y);
        registry.addTrustedIssuer(ISSUER_X, ISSUER_Y);
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
}

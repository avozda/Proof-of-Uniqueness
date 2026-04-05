// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/IdentityRegistry.sol";
import {UltraVerifier as VcOprfEnrollmentUltraVerifier} from "../src/VcOprfEnrollmentUltraVerifier.sol";

contract MockUltraVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return true;
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

contract IdentityRegistryE2ETest is Test {
    uint256 internal constant ISSUER_X = 123;
    uint256 internal constant ISSUER_Y = 456;
    uint256 internal constant OPRF_PK_X = 111;
    uint256 internal constant OPRF_PK_Y = 222;

    function _signals(uint256 nullifier, uint256 validUntil, uint256 issuerX, uint256 issuerY)
        internal
        pure
        returns (bytes32[] memory s)
    {
        s = new bytes32[](10);
        s[0] = bytes32(OPRF_PK_X);
        s[1] = bytes32(OPRF_PK_Y);
        s[2] = bytes32(validUntil);
        s[3] = bytes32(uint256(12345));
        s[4] = bytes32(uint256(67890));
        s[5] = bytes32(issuerX);
        s[6] = bytes32(issuerY);
        s[7] = bytes32(uint256(3));
        s[8] = bytes32(uint256(1));
        s[9] = bytes32(nullifier);
    }

    function testE2E_MockVerifier_EnrollAndReadBack() public {
        MockUltraVerifier mockVerifier = new MockUltraVerifier();
        MockRevocationVerifier revocationVerifier = new MockRevocationVerifier();
        IdentityRegistry registry =
            new IdentityRegistry(address(mockVerifier), address(revocationVerifier), OPRF_PK_X, OPRF_PK_Y);

        registry.addTrustedIssuer(ISSUER_X, ISSUER_Y);

        bytes memory proof = hex"01";
        bytes32[] memory signals = _signals(777, block.timestamp + 3600, ISSUER_X, ISSUER_Y);

        registry.enroll(proof, signals);

        IdentityRegistry.IdentityRecord memory record = registry.getIdentity(777);
        assertEq(record.validUntil, block.timestamp + 3600);
        assertEq(record.issuerPubKeyX, ISSUER_X);
        assertEq(record.issuerPubKeyY, ISSUER_Y);
        assertEq(record.holderPubKeyX, 12345);
        assertEq(record.holderPubKeyY, 67890);
        assertEq(record.oprfKeyId, 3);
        assertEq(record.oprfEpoch, 1);
        assertTrue(record.exists);
        assertTrue(registry.isIdentityValid(777));
        assertEq(registry.getIdentityCount(), 1);
    }

    function testE2E_RealUltraVerifier_RejectsMalformedProof() public {
        VcOprfEnrollmentUltraVerifier realVerifier = new VcOprfEnrollmentUltraVerifier();
        MockRevocationVerifier revocationVerifier = new MockRevocationVerifier();
        IdentityRegistry registry =
            new IdentityRegistry(address(realVerifier), address(revocationVerifier), OPRF_PK_X, OPRF_PK_Y);

        registry.addTrustedIssuer(ISSUER_X, ISSUER_Y);

        bytes memory malformedProof = hex"deadbeef";
        bytes32[] memory signals = _signals(888, block.timestamp + 3600, ISSUER_X, ISSUER_Y);

        vm.expectRevert(IdentityRegistry.InvalidProof.selector);
        registry.enroll(malformedProof, signals);
    }

    function testE2E_RevertOnUntrustedOprfKey() public {
        MockUltraVerifier mockVerifier = new MockUltraVerifier();
        MockRevocationVerifier revocationVerifier = new MockRevocationVerifier();
        IdentityRegistry registry =
            new IdentityRegistry(address(mockVerifier), address(revocationVerifier), OPRF_PK_X, OPRF_PK_Y);

        registry.addTrustedIssuer(ISSUER_X, ISSUER_Y);

        bytes memory proof = hex"01";
        bytes32[] memory signals = _signals(999, block.timestamp + 3600, ISSUER_X, ISSUER_Y);
        signals[0] = bytes32(uint256(OPRF_PK_X + 1));

        vm.expectRevert(IdentityRegistry.UntrustedOprfPublicKey.selector);
        registry.enroll(proof, signals);
    }

    function testE2E_RevokeDeletesIdentity() public {
        MockUltraVerifier mockVerifier = new MockUltraVerifier();
        MockRevocationVerifier revocationVerifier = new MockRevocationVerifier();
        IdentityRegistry registry =
            new IdentityRegistry(address(mockVerifier), address(revocationVerifier), OPRF_PK_X, OPRF_PK_Y);

        registry.addTrustedIssuer(ISSUER_X, ISSUER_Y);
        registry.enroll(hex"01", _signals(777, block.timestamp + 3600, ISSUER_X, ISSUER_Y));

        uint256 challengeBlock = block.number - 1;
        bytes32[] memory revokeSignals = new bytes32[](4);
        revokeSignals[0] = bytes32(uint256(777));
        revokeSignals[1] = bytes32(uint256(12345));
        revokeSignals[2] = bytes32(uint256(67890));
        revokeSignals[3] = bytes32(uint256(blockhash(challengeBlock)) % 21888242871839275222246405745257275088548364400416034343698204186575808495617);

        registry.revoke(hex"01", revokeSignals, challengeBlock);

        vm.expectRevert(IdentityRegistry.IdentityNotFound.selector);
        registry.getIdentity(777);
    }
}

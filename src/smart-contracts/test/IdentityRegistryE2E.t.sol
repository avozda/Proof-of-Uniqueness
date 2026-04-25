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

contract IdentityRegistryE2ETest is Test {
    uint256 internal constant ISSUER_X = 123;
    uint256 internal constant ISSUER_Y = 456;
    uint256 internal constant OPRF_PK_X = 111;
    uint256 internal constant OPRF_PK_Y = 222;
    uint256 internal constant REVOCATION_PRIVATE_KEY = 0xA11CE;

    function _signals(uint256 nullifier, uint256 validUntil, uint256 issuerX, uint256 issuerY, address walletAddress)
        internal
        pure
        returns (bytes32[] memory s)
    {
        s = new bytes32[](7);
        s[0] = bytes32(OPRF_PK_X);
        s[1] = bytes32(OPRF_PK_Y);
        s[2] = bytes32(validUntil);
        s[3] = bytes32(issuerX);
        s[4] = bytes32(issuerY);
        s[5] = bytes32(uint256(uint160(walletAddress)));
        s[6] = bytes32(nullifier);
    }

    function _walletAddress() internal view returns (address) {
        return vm.addr(REVOCATION_PRIVATE_KEY);
    }

    function _sign(uint256 privateKey, bytes32 digest) internal view returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _enroll(IdentityRegistry registry, bytes memory proof, bytes32[] memory signals, address walletAddress)
        internal
    {
        bytes memory signature =
            _sign(REVOCATION_PRIVATE_KEY, registry.hashEnrollmentAuthorization(proof, signals, walletAddress));
        registry.enroll(proof, signals, walletAddress, signature);
    }

    function testE2E_MockVerifier_EnrollAndReadBack() public {
        MockUltraVerifier mockVerifier = new MockUltraVerifier();
        IdentityRegistry registry = new IdentityRegistry(address(mockVerifier), OPRF_PK_X, OPRF_PK_Y);

        registry.addTrustedIssuer(ISSUER_X, ISSUER_Y);

        bytes memory proof = hex"01";
        bytes32[] memory signals = _signals(777, block.timestamp + 3600, ISSUER_X, ISSUER_Y, _walletAddress());

        _enroll(registry, proof, signals, _walletAddress());

        IdentityRegistry.IdentityRecord memory record = registry.getIdentity(777);
        assertEq(record.validUntil, block.timestamp + 3600);
        assertEq(record.issuerPubKeyX, ISSUER_X);
        assertEq(record.issuerPubKeyY, ISSUER_Y);
        assertEq(record.walletAddress, _walletAddress());
        assertTrue(record.exists);
        assertTrue(registry.isIdentityValid(777));
        assertEq(registry.getIdentityCount(), 1);
    }

    function testE2E_RealUltraVerifier_RejectsMalformedProof() public {
        VcOprfEnrollmentUltraVerifier realVerifier = new VcOprfEnrollmentUltraVerifier();
        IdentityRegistry registry = new IdentityRegistry(address(realVerifier), OPRF_PK_X, OPRF_PK_Y);

        registry.addTrustedIssuer(ISSUER_X, ISSUER_Y);

        bytes memory malformedProof = hex"deadbeef";
        bytes32[] memory signals = _signals(888, block.timestamp + 3600, ISSUER_X, ISSUER_Y, _walletAddress());
        bytes memory signature = _sign(
            REVOCATION_PRIVATE_KEY,
            registry.hashEnrollmentAuthorization(malformedProof, signals, _walletAddress())
        );

        vm.expectRevert(IdentityRegistry.InvalidProof.selector);
        registry.enroll(malformedProof, signals, _walletAddress(), signature);
    }

    function testE2E_RevertOnUntrustedOprfKey() public {
        MockUltraVerifier mockVerifier = new MockUltraVerifier();
        IdentityRegistry registry = new IdentityRegistry(address(mockVerifier), OPRF_PK_X, OPRF_PK_Y);

        registry.addTrustedIssuer(ISSUER_X, ISSUER_Y);

        bytes memory proof = hex"01";
        bytes32[] memory signals = _signals(999, block.timestamp + 3600, ISSUER_X, ISSUER_Y, _walletAddress());
        signals[0] = bytes32(uint256(OPRF_PK_X + 1));

        vm.expectRevert(IdentityRegistry.UntrustedOprfPublicKey.selector);
        registry.enroll(proof, signals, _walletAddress(), hex"01");
    }

    function testE2E_RevokeDeletesIdentity() public {
        MockUltraVerifier mockVerifier = new MockUltraVerifier();
        IdentityRegistry registry = new IdentityRegistry(address(mockVerifier), OPRF_PK_X, OPRF_PK_Y);

        registry.addTrustedIssuer(ISSUER_X, ISSUER_Y);
        _enroll(
            registry,
            hex"01",
            _signals(777, block.timestamp + 3600, ISSUER_X, ISSUER_Y, _walletAddress()),
            _walletAddress()
        );

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = _sign(REVOCATION_PRIVATE_KEY, registry.hashRevocationAuthorization(777, deadline));
        registry.revoke(777, deadline, signature);

        vm.expectRevert(IdentityRegistry.IdentityNotFound.selector);
        registry.getIdentity(777);
    }
}

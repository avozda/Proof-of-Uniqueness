// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/IdentityRegistry.sol";

contract MockUltraVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return true;
    }
}

contract IdentityRegistryScalingTest is Test {
    IdentityRegistry public registry;
    MockUltraVerifier public verifier;

    uint256 public constant ISSUER_X = 123;
    uint256 public constant ISSUER_Y = 456;
    uint256 public constant OPRF_PK_X = 111;
    uint256 public constant OPRF_PK_Y = 222;
    uint256 public constant REVOCATION_PRIVATE_KEY = 0xA11CE;
    address public walletAddress;

    function setUp() public {
        verifier = new MockUltraVerifier();
        registry = new IdentityRegistry(address(verifier), OPRF_PK_X, OPRF_PK_Y);
        registry.addTrustedIssuer(ISSUER_X, ISSUER_Y);
        walletAddress = vm.addr(REVOCATION_PRIVATE_KEY);
    }

    function _sign(bytes32 digest) internal view returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(REVOCATION_PRIVATE_KEY, digest);
        return abi.encodePacked(r, s, v);
    }

    function _enroll(bytes memory proof, bytes32[] memory signals) internal {
        registry.enroll(
            proof, signals, walletAddress, _sign(registry.hashEnrollmentAuthorization(proof, signals, walletAddress))
        );
    }

    function _enroll(IdentityRegistry target, bytes memory proof, bytes32[] memory signals) internal {
        target.enroll(
            proof, signals, walletAddress, _sign(target.hashEnrollmentAuthorization(proof, signals, walletAddress))
        );
    }

    function _newRegistry() internal returns (IdentityRegistry fresh) {
        fresh = new IdentityRegistry(address(verifier), OPRF_PK_X, OPRF_PK_Y);
        fresh.addTrustedIssuer(ISSUER_X, ISSUER_Y);
    }

    function _signals(uint256 nullifier, uint256 validUntil) internal view returns (bytes32[] memory signals) {
        signals = new bytes32[](7);
        signals[0] = bytes32(OPRF_PK_X);
        signals[1] = bytes32(OPRF_PK_Y);
        signals[2] = bytes32(validUntil);
        signals[3] = bytes32(ISSUER_X);
        signals[4] = bytes32(ISSUER_Y);
        signals[5] = bytes32(uint256(uint160(walletAddress)));
        signals[6] = bytes32(nullifier);
    }

    function _populate(IdentityRegistry target, uint256 firstNullifier, uint256 count, uint256 validUntil) internal {
        bytes memory proof = hex"01";
        for (uint256 i = 0; i < count; i++) {
            _enroll(target, proof, _signals(firstNullifier + i, validUntil));
        }
    }

    function testEnrollmentScaling() public {
        bytes memory proof = hex"01";
        bytes32[] memory signals = new bytes32[](7);

        signals[0] = bytes32(OPRF_PK_X);
        signals[1] = bytes32(OPRF_PK_Y);
        signals[2] = bytes32(block.timestamp + 1000);
        signals[3] = bytes32(ISSUER_X);
        signals[4] = bytes32(ISSUER_Y);
        signals[5] = bytes32(uint256(uint160(walletAddress)));

        console.log("Measuring gas cost for sequential enrollments:");

        signals[6] = bytes32(uint256(1));
        uint256 gasStart = gasleft();
        _enroll(proof, signals);
        uint256 gasUsed1 = gasStart - gasleft();
        console.log("Enrollment #1:", gasUsed1);

        for (uint256 i = 2; i < 100; i++) {
            signals[6] = bytes32(i);
            _enroll(proof, signals);
        }

        signals[6] = bytes32(uint256(100));
        gasStart = gasleft();
        _enroll(proof, signals);
        uint256 gasUsed100 = gasStart - gasleft();
        console.log("Enrollment #100:", gasUsed100);

        for (uint256 i = 101; i < 1000; i++) {
            signals[6] = bytes32(i);
            _enroll(proof, signals);
        }

        signals[6] = bytes32(uint256(1000));
        gasStart = gasleft();
        _enroll(proof, signals);
        uint256 gasUsed1000 = gasStart - gasleft();
        console.log("Enrollment #1000:", gasUsed1000);

        assertApproxEqAbs(gasUsed100, gasUsed1000, 300);
    }

    function testPurgeInvalidRecordsGasProfile() public {
        uint256[5] memory sizes = [uint256(1), uint256(10), uint256(100), uint256(500), uint256(1000)];
        uint256[5] memory liveScanGas;

        console.log("Measuring purgeInvalidRecords gas profile:");

        for (uint256 i = 0; i < sizes.length; i++) {
            IdentityRegistry fresh = _newRegistry();
            _populate(fresh, 10_000 + (i * 10_000), sizes[i], block.timestamp + 1000);

            uint256 gasStart = gasleft();
            uint256 purged = fresh.purgeInvalidRecords();
            liveScanGas[i] = gasStart - gasleft();

            assertEq(purged, 0);
            console.log("Purge live records:", sizes[i]);
            console.log("Purge live scan gas:", liveScanGas[i]);
            console.log("Purge live scan gas per record:", liveScanGas[i] / sizes[i]);
        }

        for (uint256 i = 0; i < sizes.length; i++) {
            IdentityRegistry fresh = _newRegistry();
            _populate(fresh, 100_000 + (i * 10_000), sizes[i], block.timestamp + 1);
            vm.warp(block.timestamp + 2);

            uint256 gasStart = gasleft();
            uint256 purged = fresh.purgeInvalidRecords();
            uint256 removeGas = gasStart - gasleft();

            assertEq(purged, sizes[i]);
            assertEq(fresh.getIdentityCount(), 0);
            console.log("Purge removed records:", sizes[i]);
            console.log("Purge remove gas:", removeGas);
            console.log("Purge remove gas per record:", removeGas / sizes[i]);
            console.log("Purge marginal remove gas per record:", (removeGas - liveScanGas[i]) / sizes[i]);

            gasStart = gasleft();
            purged = fresh.purgeInvalidRecords();
            uint256 emptyScanGas = gasStart - gasleft();

            assertEq(purged, 0);
            assertEq(fresh.getIdentityCount(), 0);
            console.log("Purge post-removal active records:", fresh.getIdentityCount());
            console.log("Purge post-removal empty scan gas:", emptyScanGas);
        }
    }
}

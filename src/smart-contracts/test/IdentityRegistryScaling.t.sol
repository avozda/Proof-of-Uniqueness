// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/IdentityRegistry.sol";

contract MockUltraVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return true;
    }
}

contract MockRevocationVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return true;
    }
}

contract IdentityRegistryScalingTest is Test {
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

    function testEnrollmentScaling() public {
        bytes memory proof = hex"01";
        bytes32[] memory signals = new bytes32[](10);

        signals[0] = bytes32(OPRF_PK_X);
        signals[1] = bytes32(OPRF_PK_Y);
        signals[2] = bytes32(block.timestamp + 1000);
        signals[3] = bytes32(uint256(1234));
        signals[4] = bytes32(uint256(4321));
        signals[5] = bytes32(ISSUER_X);
        signals[6] = bytes32(ISSUER_Y);
        signals[7] = bytes32(uint256(3));
        signals[8] = bytes32(uint256(1));

        console.log("Measuring gas cost for sequential enrollments:");

        signals[9] = bytes32(uint256(1));
        uint256 gasStart = gasleft();
        registry.enroll(proof, signals);
        uint256 gasUsed1 = gasStart - gasleft();
        console.log("Enrollment #1:", gasUsed1);

        for (uint256 i = 2; i < 100; i++) {
            signals[9] = bytes32(i);
            registry.enroll(proof, signals);
        }

        signals[9] = bytes32(uint256(100));
        gasStart = gasleft();
        registry.enroll(proof, signals);
        uint256 gasUsed100 = gasStart - gasleft();
        console.log("Enrollment #100:", gasUsed100);

        for (uint256 i = 101; i < 1000; i++) {
            signals[9] = bytes32(i);
            registry.enroll(proof, signals);
        }

        signals[9] = bytes32(uint256(1000));
        gasStart = gasleft();
        registry.enroll(proof, signals);
        uint256 gasUsed1000 = gasStart - gasleft();
        console.log("Enrollment #1000:", gasUsed1000);

        assertApproxEqAbs(gasUsed100, gasUsed1000, 100);
    }
}

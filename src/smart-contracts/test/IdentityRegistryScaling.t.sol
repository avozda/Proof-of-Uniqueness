// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/IdentityRegistry.sol";
import "../src/Groth16Verifier.sol";

contract MockVerifier {
    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[8] calldata
    ) external pure returns (bool) {
        return true;
    }
}

contract MockRevocationVerifier {
    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[4] calldata
    ) external pure returns (bool) {
        return true;
    }
}

contract IdentityRegistryScalingTest is Test {
    IdentityRegistry public registry;
    MockVerifier public verifier;
    MockRevocationVerifier public revocationVerifier;

    uint256 public constant ISSUER_X = 123;
    uint256 public constant ISSUER_Y = 456;

    function setUp() public {
        verifier = new MockVerifier();
        revocationVerifier = new MockRevocationVerifier();
        registry = new IdentityRegistry(
            address(verifier),
            address(revocationVerifier)
        );
        registry.addTrustedIssuer(ISSUER_X, ISSUER_Y);
    }

    function testEnrollmentScaling() public {
        uint256[2] memory pA;
        uint256[2][2] memory pB;
        uint256[2] memory pC;
        uint256[8] memory pubSignals;
        
        pubSignals[1] = 0; // issuer field
        pubSignals[2] = block.timestamp + 1000; // validUntil
        pubSignals[3] = 999;
        pubSignals[4] = 1234;
        pubSignals[5] = 4321;
        pubSignals[6] = ISSUER_X;
        pubSignals[7] = ISSUER_Y;

        console.log("Measuring gas cost for sequential enrollments:");
        
        // Enroll 1st identity
        pubSignals[0] = 1;
        uint256 gasStart = gasleft();
        registry.enroll(pA, pB, pC, pubSignals);
        uint256 gasUsed1 = gasStart - gasleft();
        console.log("Enrollment #1:", gasUsed1);

        // Fast forward and enroll 100th identity
        for(uint256 i = 2; i < 100; i++) {
            pubSignals[0] = i;
            registry.enroll(pA, pB, pC, pubSignals);
        }
        
        pubSignals[0] = 100;
        gasStart = gasleft();
        registry.enroll(pA, pB, pC, pubSignals);
        uint256 gasUsed100 = gasStart - gasleft();
        console.log("Enrollment #100:", gasUsed100);

        // Fast forward and enroll 1000th identity
        for(uint256 i = 101; i < 1000; i++) {
            pubSignals[0] = i;
            registry.enroll(pA, pB, pC, pubSignals);
        }
        
        pubSignals[0] = 1000;
        gasStart = gasleft();
        registry.enroll(pA, pB, pC, pubSignals);
        uint256 gasUsed1000 = gasStart - gasleft();
        console.log("Enrollment #1000:", gasUsed1000);
        
        // Assert that gas cost remains constant (O(1))
        // Small variations might occur due to EVM cold/warm slot refunds, 
        // but it shouldn't grow linearly.
        assertApproxEqAbs(gasUsed100, gasUsed1000, 100);
    }
}

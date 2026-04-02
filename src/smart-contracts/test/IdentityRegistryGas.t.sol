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

contract IdentityRegistryGasTest is Test {
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

    function testGasEnroll() public {
        uint256[2] memory pA;
        uint256[2][2] memory pB;
        uint256[2] memory pC;
        uint256[8] memory pubSignals;
        
        pubSignals[0] = 777; // hashID
        pubSignals[1] = 0; // issuer field
        pubSignals[2] = block.timestamp + 1000; // validUntil
        pubSignals[3] = 999; // sketchHash
        
        pubSignals[4] = 12345; // holderPubKeyX
        pubSignals[5] = 67890; // holderPubKeyY
        
        pubSignals[6] = ISSUER_X;
        pubSignals[7] = ISSUER_Y;

        registry.enroll(pA, pB, pC, pubSignals);
    }
    
    function testGasRevoke() public {
        testGasEnroll();

        uint256[2] memory pA;
        uint256[2][2] memory pB;
        uint256[2] memory pC;
        uint256[8] memory pubSignals;
        pubSignals[0] = 888;
        pubSignals[2] = block.timestamp + 1000;
        pubSignals[4] = 11;
        pubSignals[5] = 22;
        pubSignals[6] = ISSUER_X;
        pubSignals[7] = ISSUER_Y;
        registry.enroll(pA, pB, pC, pubSignals);

        uint256[4] memory revokeSignals;
        revokeSignals[0] = 11;
        revokeSignals[1] = 22;
        revokeSignals[2] = 888;
        revokeSignals[3] = block.number;

        registry.revokeIdentityWithProof(pA, pB, pC, revokeSignals);
    }

    function testGasPurge() public {
        testGasEnroll();
        
        // Fast forward blockchain time to trigger expiration
        vm.warp(block.timestamp + 2000);
        
        registry.purgeInvalidRecords(10);
    }
}

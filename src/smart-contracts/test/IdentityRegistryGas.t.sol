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

contract IdentityRegistryGasTest is Test {
    IdentityRegistry public registry;
    MockVerifier public verifier;

    uint256 public constant ISSUER_X = 123;
    uint256 public constant ISSUER_Y = 456;

    function setUp() public {
        verifier = new MockVerifier();
        registry = new IdentityRegistry(address(verifier));
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
        
        // Use address-form verification key formatting
        pubSignals[4] = uint256(uint160(address(0x123))); // verificationKeyX
        pubSignals[5] = 0; // verificationKeyY
        
        pubSignals[6] = ISSUER_X;
        pubSignals[7] = ISSUER_Y;

        registry.enroll(pA, pB, pC, pubSignals);
    }
    
    function testGasRevoke() public {
        testGasEnroll();
        
        uint256 challengeBlock = block.number;
        
        (address signer, uint256 pk) = makeAddrAndKey("signer");
        
        // Enroll an identity bounded to the real signer address so we can ecrecover
        uint256[2] memory pA;
        uint256[2][2] memory pB;
        uint256[2] memory pC;
        uint256[8] memory pubSignals;
        pubSignals[0] = 888; // new hashID
        pubSignals[2] = block.timestamp + 1000;
        pubSignals[4] = uint256(uint160(signer)); // Store address in X coordinate
        pubSignals[6] = ISSUER_X;
        pubSignals[7] = ISSUER_Y;
        registry.enroll(pA, pB, pC, pubSignals);
        
        // Recreate the strict challenge digest from IdentityRegistry.sol
        bytes32 challengeDigest = keccak256(
            abi.encode(
                keccak256("IdentityRegistry::Revoke:v1"),
                address(registry),
                block.chainid,
                uint256(888),
                challengeBlock
            )
        );
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, challengeDigest);
        
        registry.revokeIdentity(888, challengeBlock, v, r, s);
    }

    function testGasPurge() public {
        testGasEnroll();
        
        // Fast forward blockchain time to trigger expiration
        vm.warp(block.timestamp + 2000);
        
        registry.purgeInvalidRecords(10);
    }
}

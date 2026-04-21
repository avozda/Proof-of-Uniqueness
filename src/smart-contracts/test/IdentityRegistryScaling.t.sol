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
    address public revocationAddress;

    function setUp() public {
        verifier = new MockUltraVerifier();
        registry = new IdentityRegistry(address(verifier), OPRF_PK_X, OPRF_PK_Y);
        registry.addTrustedIssuer(ISSUER_X, ISSUER_Y);
        revocationAddress = vm.addr(REVOCATION_PRIVATE_KEY);
    }

    function _sign(bytes32 digest) internal view returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(REVOCATION_PRIVATE_KEY, digest);
        return abi.encodePacked(r, s, v);
    }

    function _enroll(bytes memory proof, bytes32[] memory signals) internal {
        registry.enroll(
            proof,
            signals,
            revocationAddress,
            _sign(registry.hashEnrollmentAuthorization(proof, signals, revocationAddress))
        );
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
        _enroll(proof, signals);
        uint256 gasUsed1 = gasStart - gasleft();
        console.log("Enrollment #1:", gasUsed1);

        for (uint256 i = 2; i < 100; i++) {
            signals[9] = bytes32(i);
            _enroll(proof, signals);
        }

        signals[9] = bytes32(uint256(100));
        gasStart = gasleft();
        _enroll(proof, signals);
        uint256 gasUsed100 = gasStart - gasleft();
        console.log("Enrollment #100:", gasUsed100);

        for (uint256 i = 101; i < 1000; i++) {
            signals[9] = bytes32(i);
            _enroll(proof, signals);
        }

        signals[9] = bytes32(uint256(1000));
        gasStart = gasleft();
        _enroll(proof, signals);
        uint256 gasUsed1000 = gasStart - gasleft();
        console.log("Enrollment #1000:", gasUsed1000);

        assertApproxEqAbs(gasUsed100, gasUsed1000, 300);
    }
}

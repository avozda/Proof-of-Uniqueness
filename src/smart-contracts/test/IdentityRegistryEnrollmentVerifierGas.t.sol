// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {IdentityRegistry} from "../src/IdentityRegistry.sol";
import {UltraVerifier as VcOprfEnrollmentUltraVerifier} from "../src/VcOprfEnrollmentUltraVerifier.sol";

contract IdentityRegistryEnrollmentVerifierGasTest is Test {
    using stdJson for string;

    uint256 internal constant ENROLLMENT_PRIVATE_KEY = 0xA11CE;
    uint256 internal constant ENROLLMENT_PROOF_BYTES = 2144;
    uint256 internal constant ENROLLMENT_PUBLIC_SIGNALS = 7;

    VcOprfEnrollmentUltraVerifier public verifier;
    IdentityRegistry public registry;

    bytes public proof;
    bytes32[] public publicSignals;
    address public walletAddress;

    function setUp() public {
        string memory json = vm.readFile("test/fixtures/vc_oprf_enrollment_proof.json");
        proof = json.readBytes(".proof");
        publicSignals = json.readBytes32Array(".publicSignals");
        walletAddress = vm.addr(ENROLLMENT_PRIVATE_KEY);

        assertEq(proof.length, ENROLLMENT_PROOF_BYTES);
        assertEq(publicSignals.length, ENROLLMENT_PUBLIC_SIGNALS);
        assertEq(address(uint160(uint256(publicSignals[5]))), walletAddress);

        verifier = new VcOprfEnrollmentUltraVerifier();
        registry = new IdentityRegistry(address(verifier), uint256(publicSignals[0]), uint256(publicSignals[1]));
        registry.addTrustedIssuer(uint256(publicSignals[3]), uint256(publicSignals[4]));
    }

    function _signEnrollment() internal view returns (bytes memory signature) {
        bytes32 digest = registry.hashEnrollmentAuthorization(proof, publicSignals, walletAddress);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ENROLLMENT_PRIVATE_KEY, digest);
        return abi.encodePacked(r, s, v);
    }

    function testGasRealEnrollmentVerifierOnly() public view {
        assertTrue(verifier.verify(proof, publicSignals));
    }

    function testGasEnrollWithRealEnrollmentVerifier() public {
        registry.enroll(proof, publicSignals, walletAddress, _signEnrollment());

        uint256 nullifier = uint256(publicSignals[6]);
        IdentityRegistry.IdentityRecord memory record = registry.getIdentity(nullifier);
        assertEq(record.walletAddress, walletAddress);
        assertTrue(record.exists);
    }
}

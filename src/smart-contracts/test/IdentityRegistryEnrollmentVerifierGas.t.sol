// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/StdJson.sol";
import "../src/IdentityRegistry.sol";
import {UltraVerifier as VcOprfEnrollmentUltraVerifier} from "../src/VcOprfEnrollmentUltraVerifier.sol";

contract IdentityRegistryEnrollmentVerifierGasTest is Test {
    using stdJson for string;

    uint256 internal constant REVOCATION_PRIVATE_KEY = 0xA11CE;

    VcOprfEnrollmentUltraVerifier public verifier;
    IdentityRegistry public registry;

    bytes public proof;
    bytes32[] public publicSignals;
    address public walletAddress;

    function setUp() public {
        string memory json = vm.readFile("test/fixtures/vc_oprf_enrollment_proof.json");
        proof = json.readBytes(".proof");
        publicSignals = json.readBytes32Array(".publicSignals");
        walletAddress = vm.addr(REVOCATION_PRIVATE_KEY);

        verifier = new VcOprfEnrollmentUltraVerifier();
        registry = new IdentityRegistry(address(verifier), uint256(publicSignals[0]), uint256(publicSignals[1]));
        registry.addTrustedIssuer(uint256(publicSignals[3]), uint256(publicSignals[4]));
    }

    function _signEnrollment() internal view returns (bytes memory signature) {
        bytes32 digest = registry.hashEnrollmentAuthorization(proof, publicSignals, walletAddress);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(REVOCATION_PRIVATE_KEY, digest);
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

// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {IdentityRegistry} from "../src/IdentityRegistry.sol";
import {UltraVerifier as VcOprfEnrollmentUltraVerifier} from "../src/VcOprfEnrollmentUltraVerifier.sol";
import {HonkVerifier as VcRevocationUltraVerifier} from "../src/VcRevocationUltraVerifier.sol";

contract IdentityRegistryScript is Script {
    VcOprfEnrollmentUltraVerifier public verifier;
    VcRevocationUltraVerifier public revocationVerifier;
    IdentityRegistry public identityRegistry;

    // Default trusted issuer public key (replace with actual issuer keys in production)
    // These are example values - update with real issuer public key coordinates
    uint256 constant DEFAULT_ISSUER_PUB_KEY_X =
        10071275662669496964271891637364776704118012876696603923297770253753452927428;
    uint256 constant DEFAULT_ISSUER_PUB_KEY_Y =
        8997364839704209737650887068131023238259636247140575704234779417606488967006;
    uint256 constant DEFAULT_OPRF_PUB_KEY_X =
        15003657924788399520423800501973962387080403835278072811641574091656004606719;
    uint256 constant DEFAULT_OPRF_PUB_KEY_Y =
        14529415343323015636900366522580262473735574267701282924026299349812458958307;

    function setUp() public {}

    function run() public {
        uint256 trustedOprfPkX = vm.envOr("OPRF_PUB_KEY_X", DEFAULT_OPRF_PUB_KEY_X);
        uint256 trustedOprfPkY = vm.envOr("OPRF_PUB_KEY_Y", DEFAULT_OPRF_PUB_KEY_Y);

        vm.startBroadcast();

        // Deploy the VC+OPRF Ultra verifier
        verifier = new VcOprfEnrollmentUltraVerifier();
        console.log("VcOprfEnrollmentUltraVerifier deployed at:", address(verifier));
        require(address(verifier).code.length > 0, "Verifier deployment failed (no runtime code)");

        revocationVerifier = new VcRevocationUltraVerifier();
        console.log("VcRevocationUltraVerifier deployed at:", address(revocationVerifier));
        require(address(revocationVerifier).code.length > 0, "Revocation verifier deployment failed (no runtime code)");

        // Deploy IdentityRegistry with the verifier address
        identityRegistry = new IdentityRegistry(
            address(verifier),
            address(revocationVerifier),
            trustedOprfPkX,
            trustedOprfPkY
        );
        console.log("IdentityRegistry deployed at:", address(identityRegistry));
        console.log("Trusted OPRF public key X:", trustedOprfPkX);
        console.log("Trusted OPRF public key Y:", trustedOprfPkY);

        // Add default trusted issuer if configured
        if (DEFAULT_ISSUER_PUB_KEY_X != 0 && DEFAULT_ISSUER_PUB_KEY_Y != 0) {
            identityRegistry.addTrustedIssuer(DEFAULT_ISSUER_PUB_KEY_X, DEFAULT_ISSUER_PUB_KEY_Y);
            console.log("Default trusted issuer added");
        }

        vm.stopBroadcast();
    }
}

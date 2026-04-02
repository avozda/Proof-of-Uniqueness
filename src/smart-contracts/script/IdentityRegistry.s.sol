// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {IdentityRegistry} from "../src/IdentityRegistry.sol";
import {Groth16Verifier} from "../src/Groth16Verifier.sol";
import {Groth16RevocationVerifier} from "../src/Groth16RevocationVerifier.sol";

contract IdentityRegistryScript is Script {
    Groth16Verifier public verifier;
    Groth16RevocationVerifier public revocationVerifier;
    IdentityRegistry public identityRegistry;

    // Default trusted issuer public key (replace with actual issuer keys in production)
    // These are example values - update with real issuer public key coordinates
    uint256 constant DEFAULT_ISSUER_PUB_KEY_X =
        10071275662669496964271891637364776704118012876696603923297770253753452927428;
    uint256 constant DEFAULT_ISSUER_PUB_KEY_Y =
        8997364839704209737650887068131023238259636247140575704234779417606488967006;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        // Deploy the Groth16 verifier
        verifier = new Groth16Verifier();
        console.log("Groth16Verifier deployed at:", address(verifier));

        revocationVerifier = new Groth16RevocationVerifier();
        console.log(
            "Groth16RevocationVerifier deployed at:",
            address(revocationVerifier)
        );

        // Deploy IdentityRegistry with the verifier address
        identityRegistry = new IdentityRegistry(
            address(verifier),
            address(revocationVerifier)
        );
        console.log(
            "IdentityRegistry deployed at:",
            address(identityRegistry)
        );

        // Add default trusted issuer if configured
        if (DEFAULT_ISSUER_PUB_KEY_X != 0 && DEFAULT_ISSUER_PUB_KEY_Y != 0) {
            identityRegistry.addTrustedIssuer(
                DEFAULT_ISSUER_PUB_KEY_X,
                DEFAULT_ISSUER_PUB_KEY_Y
            );
            console.log("Default trusted issuer added");
        }

        vm.stopBroadcast();
    }
}

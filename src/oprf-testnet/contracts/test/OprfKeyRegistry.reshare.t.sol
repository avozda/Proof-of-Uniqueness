// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {BabyJubJub} from "@taceo/babyjubjub/BabyJubJub.sol";
import {Contributions} from "./Contributions.t.sol";
import {OprfKeyGen} from "../src/OprfKeyGen.sol";
import {OprfKeyRegistry} from "../src/OprfKeyRegistry.sol";
import {OprfKeyRegistryKeyGenTest} from "./OprfKeyRegistry.keygen.t.sol";
import {Test} from "forge-std/Test.sol";

contract OprfKeyRegistryReshareTest is Test, OprfKeyRegistryKeyGenTest {
    using BabyJubJub for BabyJubJub.Affine;

    function testReshare1() public {
        testKeyGen();
        reshare1();
    }

    function testReshare2() public {
        testReshare1();
        reshare2();
    }

    function testReshare1ThenDelete() public {
        uint160 oprfKeyId = 42;
        testKeyGen();
        reshare1();

        deleteOprfKey(oprfKeyId);
        checkGeneratedIsDeleted(oprfKeyId);

        // check cannot start key-gen/reshare
        vm.prank(taceoAdmin);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.DeletedId.selector, 42));
        oprfKeyRegistry.initKeyGen(oprfKeyId);

        vm.prank(taceoAdmin);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.DeletedId.selector, 42));
        oprfKeyRegistry.initReshare(oprfKeyId);
        vm.stopPrank();
    }

    function testReshare2ThenDelete() public {
        uint160 oprfKeyId = 42;
        testReshare1();
        reshare2();

        deleteOprfKey(oprfKeyId);
        checkGeneratedIsDeleted(oprfKeyId);

        // check cannot start key-gen/reshare
        vm.prank(taceoAdmin);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.DeletedId.selector, 42));
        oprfKeyRegistry.initKeyGen(oprfKeyId);

        vm.prank(taceoAdmin);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.DeletedId.selector, 42));
        oprfKeyRegistry.initReshare(oprfKeyId);
        vm.stopPrank();
    }

    function testInitReshareResubmit() public {
        uint160 oprfKeyId = 42;
        uint32 generatedEpoch = 1;
        testKeyGen();
        initReshare(oprfKeyId, generatedEpoch);

        vm.prank(taceoAdmin);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.AlreadySubmitted.selector));
        oprfKeyRegistry.initReshare(oprfKeyId);

        vm.prank(taceoAdmin);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.AlreadySubmitted.selector));
        oprfKeyRegistry.initKeyGen(oprfKeyId);
    }

    function reshare1() private {
        uint160 oprfKeyId = 42;
        uint32 generatedEpoch = 1;

        initReshare(oprfKeyId, generatedEpoch);

        reshare1Round1Contributions(oprfKeyId, generatedEpoch);
        reshare1Round2Contributions(oprfKeyId, generatedEpoch);
        reshare1Round3Contributions(oprfKeyId, generatedEpoch);

        // check that the computed key is correct
        checkGeneratedKey(oprfKeyId, generatedEpoch);
    }

    function reshare2() private {
        uint160 oprfKeyId = 42;
        uint32 generatedEpoch = 2;

        initReshare(oprfKeyId, generatedEpoch);

        reshare2Round1Contributions(oprfKeyId, generatedEpoch);
        reshare2Round2Contributions(oprfKeyId, generatedEpoch);
        reshare2Round3Contributions(oprfKeyId, generatedEpoch);

        // check that the computed key is correct
        checkGeneratedKey(oprfKeyId, generatedEpoch);
    }

    function testAbortAfterKeyGenThenReshare() public {
        uint160 oprfKeyId = 42;
        testKeyGen();

        vm.prank(taceoAdmin);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.UnknownId.selector, 42));
        emit OprfKeyGen.KeyGenAbort(oprfKeyId);
        oprfKeyRegistry.abortKeyGen(oprfKeyId);
        vm.stopPrank();

        checkGeneratedKey(oprfKeyId, 0);

        // cannot submit round 1
        vm.prank(carol);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.WrongRound.selector, 0));
        oprfKeyRegistry.addRound1ReshareContribution(oprfKeyId, Contributions.carolReshare1Round1Contribution());
        vm.stopPrank();

        // can still do a reshare 1 with correct epoch
        reshare1();
    }

    function testAbortAfterReshareThenReshare() public {
        uint160 oprfKeyId = 42;
        testReshare1();

        vm.prank(taceoAdmin);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.UnknownId.selector, 42));
        emit OprfKeyGen.KeyGenAbort(oprfKeyId);
        oprfKeyRegistry.abortKeyGen(oprfKeyId);
        vm.stopPrank();

        checkGeneratedKey(oprfKeyId, 1);

        // cannot submit round 1
        vm.prank(carol);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.WrongRound.selector, 0));
        oprfKeyRegistry.addRound1ReshareContribution(oprfKeyId, Contributions.carolReshare1Round1Contribution());
        vm.stopPrank();

        // can still do a reshare 2 with correct epoch
        reshare2();
    }

    function testAbortDuringKeyGenMultipleTimes() public {
        uint160 oprfKeyId = 42;
        initKeyGen(oprfKeyId);
        keyGenRound1Contributions(oprfKeyId);
        keyGenRound2Contributions(oprfKeyId);

        abortKeyGen(oprfKeyId);

        vm.prank(taceoAdmin);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.UnknownId.selector, 42));
        oprfKeyRegistry.abortKeyGen(oprfKeyId);
        vm.stopPrank();

        // cannot continue
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.WrongRound.selector, 0));
        oprfKeyRegistry.addRound3Contribution(oprfKeyId);
        vm.stopPrank();
    }

    function testAbortDuringKeyGenAndAddRound2Contribution() public {
        uint160 oprfKeyId = 42;
        initKeyGen(oprfKeyId);
        keyGenRound1Contributions(oprfKeyId);
        keyGenRound2Contributions(oprfKeyId);

        abortKeyGen(oprfKeyId);

        // we never create a key therefore we get unknown ID
        vm.prank(carol);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.WrongRound.selector, 0));
        oprfKeyRegistry.addRound2Contribution(oprfKeyId, Contributions.carolReshare2Round2Contribution());
        vm.stopPrank();
        testReshare2();
    }

    function testAbortDuringKeyGenAndAddRound3Contribution() public {
        uint160 oprfKeyId = 42;
        initKeyGen(oprfKeyId);
        keyGenRound1Contributions(oprfKeyId);
        keyGenRound2Contributions(oprfKeyId);

        abortKeyGen(oprfKeyId);

        // we never create a key therefore we get unknown ID
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.WrongRound.selector, 0));
        oprfKeyRegistry.addRound3Contribution(oprfKeyId);
        vm.stopPrank();
        testReshare2();
    }

    function testAbortDuringKeyGenInitAgainAndAddRound2Contribution() public {
        uint160 oprfKeyId = 42;
        initKeyGen(oprfKeyId);
        keyGenRound1Contributions(oprfKeyId);
        keyGenRound2Contributions(oprfKeyId);

        abortKeyGen(oprfKeyId);
        initKeyGen(oprfKeyId);

        // we never create a key therefore we get unknown ID
        vm.prank(carol);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.WrongRound.selector, 1));
        oprfKeyRegistry.addRound2Contribution(oprfKeyId, Contributions.carolReshare2Round2Contribution());
        vm.stopPrank();
    }

    function testAbortDuringKeyGenInitAgainAndAddRound3Contribution() public {
        uint160 oprfKeyId = 42;
        initKeyGen(oprfKeyId);
        keyGenRound1Contributions(oprfKeyId);
        keyGenRound2Contributions(oprfKeyId);

        abortKeyGen(oprfKeyId);
        initKeyGen(oprfKeyId);

        // we never create a key therefore we get unknown ID
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.WrongRound.selector, 1));
        oprfKeyRegistry.addRound3Contribution(oprfKeyId);
        vm.stopPrank();
    }

    function testAbortDuringReshareMultipleTimes() public {
        // make a normal key-gen for id 42;
        testKeyGen();
        uint32 generatedEpoch = 1;
        uint160 oprfKeyId = 42;

        initReshare(oprfKeyId, generatedEpoch);

        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 1, 1, generatedEpoch);
        oprfKeyRegistry.addRound1ReshareContribution(oprfKeyId, Contributions.bobReshare1Round1Contribution());
        vm.stopPrank();

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 0, 1, generatedEpoch);
        oprfKeyRegistry.addRound1ReshareContribution(oprfKeyId, Contributions.aliceReshare1Round1Contribution());
        vm.stopPrank();

        // abort during round 1
        abortKeyGen(oprfKeyId);

        // second abort is an error
        vm.prank(taceoAdmin);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.UnknownId.selector, 42));
        emit OprfKeyGen.KeyGenAbort(oprfKeyId);
        oprfKeyRegistry.abortKeyGen(oprfKeyId);
        vm.stopPrank();

        reshare1();
    }

    function testAbortReshareBeforeRound1() public {
        // make a normal key-gen for id 42;
        testKeyGen();
        uint160 oprfKeyId = 42;
        uint32 generatedEpoch = 1;

        initReshare(oprfKeyId, generatedEpoch);

        // abort before round 1
        abortKeyGen(oprfKeyId);

        // can still do a reshare
        reshare1();
    }

    function testAbortReshareDuringRound1() public {
        // make a normal key-gen for id 42;
        testKeyGen();
        uint32 generatedEpoch = 1;
        uint160 oprfKeyId = 42;

        initReshare(oprfKeyId, generatedEpoch);

        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 1, 1, generatedEpoch);
        oprfKeyRegistry.addRound1ReshareContribution(oprfKeyId, Contributions.bobReshare1Round1Contribution());
        vm.stopPrank();

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 0, 1, generatedEpoch);
        oprfKeyRegistry.addRound1ReshareContribution(oprfKeyId, Contributions.aliceReshare1Round1Contribution());
        vm.stopPrank();

        // abort during round 1
        abortKeyGen(oprfKeyId);
        reshare1();
    }

    function testAbortReshareBeforeRound2() public {
        // make a normal key-gen for id 42;
        testKeyGen();
        uint32 generatedEpoch = 1;
        uint160 oprfKeyId = 42;

        initReshare(oprfKeyId, generatedEpoch);
        reshare1Round1Contributions(oprfKeyId, generatedEpoch);
        abortKeyGen(oprfKeyId);
        reshare1();
    }

    function testAbortReshareDuringRound2() public {
        // make a normal key-gen for id 42;
        testKeyGen();
        uint32 generatedEpoch = 1;
        uint160 oprfKeyId = 42;

        initReshare(oprfKeyId, generatedEpoch);
        reshare1Round1Contributions(oprfKeyId, generatedEpoch);

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 0, 2, generatedEpoch);
        oprfKeyRegistry.addRound2Contribution(oprfKeyId, Contributions.aliceReshare1Round2Contribution());
        vm.stopPrank();
        abortKeyGen(oprfKeyId);
        reshare1();
    }

    function testAbortReshareBeforeRound3() public {
        // make a normal key-gen for id 42;
        testKeyGen();
        uint32 generatedEpoch = 1;
        uint160 oprfKeyId = 42;

        initReshare(oprfKeyId, generatedEpoch);
        reshare1Round1Contributions(oprfKeyId, generatedEpoch);
        reshare1Round2Contributions(oprfKeyId, generatedEpoch);
        abortKeyGen(oprfKeyId);
        reshare1();
    }

    function testAbortReshareDuringRound3() public {
        // make a normal key-gen for id 42;
        testKeyGen();
        uint32 generatedEpoch = 1;
        uint160 oprfKeyId = 42;

        initReshare(oprfKeyId, generatedEpoch);
        reshare1Round1Contributions(oprfKeyId, generatedEpoch);
        reshare1Round2Contributions(oprfKeyId, generatedEpoch);

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 0, 3, generatedEpoch);
        oprfKeyRegistry.addRound3Contribution(oprfKeyId);
        vm.stopPrank();

        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 1, 3, generatedEpoch);
        oprfKeyRegistry.addRound3Contribution(oprfKeyId);
        vm.stopPrank();
        abortKeyGen(oprfKeyId);
        reshare1();
    }

    function testReshareIsStuck() public {
        testKeyGen();
        uint32 generatedEpoch = 1;
        uint160 oprfKeyId = 42;
        initReshare(oprfKeyId, generatedEpoch);

        OprfKeyGen.Round1Contribution memory aliceContribution = Contributions.aliceReshare1Round1Contribution();
        aliceContribution.commShare = BabyJubJub.Affine({x: 0, y: 0});
        aliceContribution.commCoeffs = 0;

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 0, 1, generatedEpoch);
        oprfKeyRegistry.addRound1ReshareContribution(oprfKeyId, aliceContribution);
        vm.stopPrank();

        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 1, 1, generatedEpoch);
        oprfKeyRegistry.addRound1ReshareContribution(oprfKeyId, Contributions.bobReshare1Round1Contribution());
        vm.stopPrank();

        vm.prank(carol);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.NotEnoughProducers(oprfKeyId);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 2, 1, generatedEpoch);
        oprfKeyRegistry.addRound1ReshareContribution(oprfKeyId, Contributions.carolReshare1Round1Contribution());
        vm.stopPrank();

        // check that we can't continue with round 2
        vm.prank(carol);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.WrongRound.selector, 4));
        oprfKeyRegistry.addRound2Contribution(oprfKeyId, Contributions.carolReshare2Round2Contribution());
        vm.stopPrank();

        // now abort
        abortKeyGen(oprfKeyId);

        // and finish
        reshare1();
        reshare2();
    }

    function initReshare(uint160 oprfKeyId, uint32 generatedEpoch) private {
        vm.prank(taceoAdmin);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.ReshareRound1(oprfKeyId, THRESHOLD, generatedEpoch);
        oprfKeyRegistry.initReshare(oprfKeyId);
        vm.stopPrank();
    }

    function reshare1Round1Contributions(uint160 oprfKeyId, uint32 generatedEpoch) private {
        // carol is a consumer here
        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 1, 1, generatedEpoch);
        oprfKeyRegistry.addRound1ReshareContribution(oprfKeyId, Contributions.bobReshare1Round1Contribution());
        vm.stopPrank();

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 0, 1, generatedEpoch);
        oprfKeyRegistry.addRound1ReshareContribution(oprfKeyId, Contributions.aliceReshare1Round1Contribution());
        vm.stopPrank();

        vm.prank(carol);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.SecretGenRound2(oprfKeyId, generatedEpoch);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 2, 1, generatedEpoch);
        oprfKeyRegistry.addRound1ReshareContribution(oprfKeyId, Contributions.carolReshare1Round1Contribution());
        vm.stopPrank();
    }

    function reshare1Round2Contributions(uint160 oprfKeyId, uint32 generatedEpoch) private {
        // do round 2 contributions
        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 0, 2, generatedEpoch);
        oprfKeyRegistry.addRound2Contribution(oprfKeyId, Contributions.aliceReshare1Round2Contribution());
        vm.stopPrank();

        vm.prank(bob);
        uint256[] memory lagrange_should = new uint256[](3);
        lagrange_should[0] = Contributions.LAGRANGE_RESHARE1_0;
        lagrange_should[1] = Contributions.LAGRANGE_RESHARE1_1;
        lagrange_should[2] = 0;
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.ReshareRound3(oprfKeyId, lagrange_should, generatedEpoch);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 1, 2, generatedEpoch);
        oprfKeyRegistry.addRound2Contribution(oprfKeyId, Contributions.bobReshare1Round2Contribution());
        vm.stopPrank();
    }

    function reshare1Round3Contributions(uint160 oprfKeyId, uint32 generatedEpoch) private {
        // do round 3 contributions
        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 0, 3, generatedEpoch);
        oprfKeyRegistry.addRound3Contribution(oprfKeyId);
        vm.stopPrank();

        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 1, 3, generatedEpoch);
        oprfKeyRegistry.addRound3Contribution(oprfKeyId);
        vm.stopPrank();

        // check that we are still in epoch 0
        OprfKeyGen.RegisteredOprfPublicKey memory oprfKeyAndEpochKeyGen =
            oprfKeyRegistry.getOprfPublicKeyAndEpoch(oprfKeyId);
        assertEq(oprfKeyAndEpochKeyGen.key.x, Contributions.SHOULD_OPRF_PUBLIC_KEY_X);
        assertEq(oprfKeyAndEpochKeyGen.key.y, Contributions.SHOULD_OPRF_PUBLIC_KEY_Y);
        assertEq(oprfKeyAndEpochKeyGen.epoch, 0);

        // last contribution
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.SecretGenFinalize(oprfKeyId, generatedEpoch);
        vm.prank(carol);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 2, 3, generatedEpoch);
        oprfKeyRegistry.addRound3Contribution(oprfKeyId);
        vm.stopPrank();
    }

    function reshare2Round1Contributions(uint160 oprfKeyId, uint32 generatedEpoch) private {
        // alice is a consumer here
        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 1, 1, generatedEpoch);
        oprfKeyRegistry.addRound1ReshareContribution(oprfKeyId, Contributions.bobReshare2Round1Contribution());
        vm.stopPrank();

        vm.prank(carol);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 2, 1, generatedEpoch);
        oprfKeyRegistry.addRound1ReshareContribution(oprfKeyId, Contributions.carolReshare2Round1Contribution());
        vm.stopPrank();

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.SecretGenRound2(oprfKeyId, generatedEpoch);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 0, 1, generatedEpoch);
        oprfKeyRegistry.addRound1ReshareContribution(oprfKeyId, Contributions.aliceReshare2Round1Contribution());
        vm.stopPrank();
    }

    function reshare2Round2Contributions(uint160 oprfKeyId, uint32 generatedEpoch) private {
        vm.prank(carol);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 2, 2, generatedEpoch);
        oprfKeyRegistry.addRound2Contribution(oprfKeyId, Contributions.carolReshare2Round2Contribution());
        vm.stopPrank();

        vm.prank(bob);
        uint256[] memory lagrange_should = new uint256[](3);
        lagrange_should[0] = 0;
        lagrange_should[1] = Contributions.LAGRANGE_RESHARE2_0;
        lagrange_should[2] = Contributions.LAGRANGE_RESHARE2_1;
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.ReshareRound3(oprfKeyId, lagrange_should, generatedEpoch);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 1, 2, generatedEpoch);
        oprfKeyRegistry.addRound2Contribution(oprfKeyId, Contributions.bobReshare2Round2Contribution());
        vm.stopPrank();
    }

    function reshare2Round3Contributions(uint160 oprfKeyId, uint32 generatedEpoch) private {
        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 0, 3, generatedEpoch);
        oprfKeyRegistry.addRound3Contribution(oprfKeyId);
        vm.stopPrank();

        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 1, 3, generatedEpoch);
        oprfKeyRegistry.addRound3Contribution(oprfKeyId);
        vm.stopPrank();

        // check that we are still in epoch 0
        OprfKeyGen.RegisteredOprfPublicKey memory oprfKeyAndEpochKeyGen =
            oprfKeyRegistry.getOprfPublicKeyAndEpoch(oprfKeyId);
        assertEq(oprfKeyAndEpochKeyGen.key.x, Contributions.SHOULD_OPRF_PUBLIC_KEY_X);
        assertEq(oprfKeyAndEpochKeyGen.key.y, Contributions.SHOULD_OPRF_PUBLIC_KEY_Y);
        assertEq(oprfKeyAndEpochKeyGen.epoch, generatedEpoch - 1);

        // last contribution
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.SecretGenFinalize(oprfKeyId, generatedEpoch);
        vm.prank(carol);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 2, 3, generatedEpoch);
        oprfKeyRegistry.addRound3Contribution(oprfKeyId);
        vm.stopPrank();
    }
}

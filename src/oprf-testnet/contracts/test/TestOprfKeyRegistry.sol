// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BabyJubJub} from "@taceo/babyjubjub/BabyJubJub.sol";
import {OprfKeyGen} from "../src/OprfKeyGen.sol";
import {OprfKeyRegistry, IVerifierKeyGen13, PUBLIC_INPUT_LENGTH_KEYGEN_13} from "../src/OprfKeyRegistry.sol";

uint256 constant INVALID_PROOF = 43;
uint256 constant WRONG_ROUND_LOAD_PEER_PUBLIC_KEYS = 44;

contract TestOprfKeyRegistry is OprfKeyRegistry {
    function emitDeleteEvent(uint160 oprfKeyId) public {
        emit OprfKeyGen.KeyDeletion(oprfKeyId);
    }

    function emitSecretGenFinalize(uint160 oprfKeyId, uint32 epoch) public {
        emit OprfKeyGen.SecretGenFinalize(oprfKeyId, epoch);
    }

    function loadPeerPublicKeysForProducers(uint160 oprfKeyId)
        public
        view
        override
        isReady
        onlyProxy
        returns (BabyJubJub.Affine[] memory)
    {
        if (WRONG_ROUND_LOAD_PEER_PUBLIC_KEYS == oprfKeyId) {
            revert WrongRound(OprfKeyGen.Round.THREE);
        }
        if (oprfKeyId == INVALID_PROOF) {
            // producer
            BabyJubJub.Affine memory p0 = BabyJubJub.Affine({
                x: 12821603125475748520011037468870418930812538699668722876863355416717947078760,
                y: 17067928114558614218231702459319414114121381971449529647004646393893219524072
            });
            BabyJubJub.Affine memory p1 = BabyJubJub.Affine({
                x: 1688152706970503579483116674764161908712002477111907598715160302455660303671,
                y: 20413269805955861205216587925478893435677791255572561712193586073128762510903
            });
            BabyJubJub.Affine memory p2 = BabyJubJub.Affine({
                x: 181606117961119882406004099351368673462695832980672617028988734026223981902,
                y: 16711318399047418081809052707903382106816693867662676821566699591386252462603
            });
            BabyJubJub.Affine[] memory pubKeyList = new BabyJubJub.Affine[](3);
            pubKeyList[0] = p0;
            pubKeyList[1] = p1;
            pubKeyList[2] = p2;
            return pubKeyList;
        } else {
            return OprfKeyRegistry.loadPeerPublicKeysForProducers(oprfKeyId);
        }
    }

    function addRound2Contribution(uint160 oprfKeyId, OprfKeyGen.Round2Contribution calldata data)
        public
        override
        onlyProxy
        isReady
    {
        if (oprfKeyId == INVALID_PROOF) {
            IVerifierKeyGen13 keyGenVerifier13 = IVerifierKeyGen13(keyGenVerifier);
            uint256[PUBLIC_INPUT_LENGTH_KEYGEN_13] memory publicInputs;
            for (uint256 i = 0; i < PUBLIC_INPUT_LENGTH_KEYGEN_13; i++) {
                publicInputs[i] = i;
            }
            keyGenVerifier13.verifyCompressedProof(data.compressedProof, publicInputs);
        } else {
            OprfKeyRegistry.addRound2Contribution(oprfKeyId, data);
        }
    }
}

// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract SMTNonMembershipVerifier {
    // Scalar field size
    uint256 constant smt_r =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant smt_q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant smt_alphax =
        16428432848801857252194528405604668803277877773566238944394625302971855135431;
    uint256 constant smt_alphay =
        16846502678714586896801519656441059708016666274385668027902869494772365009666;
    uint256 constant smt_betax1 =
        3182164110458002340215786955198810119980427837186618912744689678939861918171;
    uint256 constant smt_betax2 =
        16348171800823588416173124589066524623406261996681292662100840445103873053252;
    uint256 constant smt_betay1 =
        4920802715848186258981584729175884379674325733638798907835771393452862684714;
    uint256 constant smt_betay2 =
        19687132236965066906216944365591810874384658708175106803089633851114028275753;
    uint256 constant smt_gammax1 =
        11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant smt_gammax2 =
        10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant smt_gammay1 =
        4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant smt_gammay2 =
        8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant smt_deltax1 =
        7664561321509888658801748851733455669818412058755577985397511918893965486292;
    uint256 constant smt_deltax2 =
        15125707797259823634261336367750128931240290770477565725084277235996689344092;
    uint256 constant smt_deltay1 =
        13818278739481193801730820150716723170173411310497690701439162056818277053954;
    uint256 constant smt_deltay2 =
        6969581528809885814254438217441837926994047119678676871798298417053985876577;

    uint256 constant smt_IC0x =
        16486913520692986474079008362883165351398003839919748095455028407165737807457;
    uint256 constant smt_IC0y =
        16328900423499367605068273290506230988216685188131724043620423723756109184012;

    uint256 constant smt_IC1x =
        1201232856595018083521923564507305992998595406774970667286734950070326178085;
    uint256 constant smt_IC1y =
        17659334973380393053878681264279073657454415551368708887206398220643908701508;

    uint256 constant smt_IC2x =
        9445000162346057018832861573033474339308927348143325982370460997237555116597;
    uint256 constant smt_IC2y =
        9828789352466776052275185513419433869543466267271050970533498447809019163898;

    uint256 constant smt_IC3x =
        8200513231334596059303299993266145778623619175127914078326356511686178721494;
    uint256 constant smt_IC3y =
        16254854223821392436054178154869811621610695435003378627950995508644792107121;

    // Memory data
    uint16 constant smt_pVk = 0;
    uint16 constant smt_pPairing = 128;

    uint16 constant smt_pLastMem = 896;

    function verifySMTProof(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[3] calldata _pubSignals
    ) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, smt_r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, smt_pPairing)
                let _pVk := add(pMem, smt_pVk)

                mstore(_pVk, smt_IC0x)
                mstore(add(_pVk, 32), smt_IC0y)

                // Compute the linear combination vk_x

                g1_mulAccC(
                    _pVk,
                    smt_IC1x,
                    smt_IC1y,
                    calldataload(add(pubSignals, 0))
                )

                g1_mulAccC(
                    _pVk,
                    smt_IC2x,
                    smt_IC2y,
                    calldataload(add(pubSignals, 32))
                )

                g1_mulAccC(
                    _pVk,
                    smt_IC3x,
                    smt_IC3y,
                    calldataload(add(pubSignals, 64))
                )

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(
                    add(_pPairing, 32),
                    mod(sub(smt_q, calldataload(add(pA, 32))), smt_q)
                )

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), smt_alphax)
                mstore(add(_pPairing, 224), smt_alphay)

                // beta2
                mstore(add(_pPairing, 256), smt_betax1)
                mstore(add(_pPairing, 288), smt_betax2)
                mstore(add(_pPairing, 320), smt_betay1)
                mstore(add(_pPairing, 352), smt_betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, smt_pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(smt_pVk, 32))))

                // gamma2
                mstore(add(_pPairing, 448), smt_gammax1)
                mstore(add(_pPairing, 480), smt_gammax2)
                mstore(add(_pPairing, 512), smt_gammay1)
                mstore(add(_pPairing, 544), smt_gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), smt_deltax1)
                mstore(add(_pPairing, 672), smt_deltax2)
                mstore(add(_pPairing, 704), smt_deltay1)
                mstore(add(_pPairing, 736), smt_deltay2)

                let success := staticcall(
                    sub(gas(), 2000),
                    8,
                    _pPairing,
                    768,
                    _pPairing,
                    0x20
                )

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, smt_pLastMem))

            // Validate that all evaluations ∈ F

            checkField(calldataload(add(_pubSignals, 0)))

            checkField(calldataload(add(_pubSignals, 32)))

            checkField(calldataload(add(_pubSignals, 64)))

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
            return(0, 0x20)
        }
    }
}

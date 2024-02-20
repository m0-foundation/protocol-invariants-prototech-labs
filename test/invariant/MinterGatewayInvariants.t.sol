// SPDX-FileCopyrightText: © 2024 Prototech Labs <info@prototechlabs.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright © 2024 Christopher Mooney
// Copyright © 2024 Chris Smith
// Copyright © 2024 Brian McMichael
// Copyright © 2024 Derek Flossman
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
pragma solidity ^0.8.23;

// solhint-disable-next-line no-console, no-global-import
import "forge-std/console.sol";

import { BaseInvariants }  from "./lib/BaseInvariants.sol";
import { BaseMZeroInvariants } from "./lib/BaseMZeroInvariants.sol";
import { InvariantUtils } from "./lib/InvariantUtils.sol";
import { MinterGatewayHandler } from "./handlers/MinterGatewayHandler.sol";

import {
    MinterGateway,
    MockMToken,
    MockRateModel,
    MockTTGRegistrar,
    TTGRegistrarReader
} from "./lib/Protocol.sol";

import { Registrar } from "./lib/Ttg.sol";

contract MinterGatewayInvariants is BaseInvariants, BaseMZeroInvariants {
    MinterGatewayHandler public _minterGatewayHandler;

    function setUp() public virtual {
        if (!_integration) {
            _mockMToken = new MockMToken();
            _mockTTGRegistrar = new MockTTGRegistrar();

            _mToken.addr = address(_mockMToken);
            _registrar.addr = address(_mockTTGRegistrar);

            _mockTTGRegistrar.setVault(_distributionVault.addr);

            minterGateway = new MinterGateway(_registrar.addr, _mToken.addr);
        }

        initRegistrar();
        minterGateway.updateIndex();

        _minterGatewayHandler = new MinterGatewayHandler(
            address(this),
            minterGateway,
            Registrar(_registrar.addr)
        );

        if (!_integration) {
            _minterGatewayHandler.init(NUM_OF_ACTORS);
        } else {
            _minterGatewayHandler.init(_actors, _receivers);
        }

        // add all testable functions
        bytes4[] memory selectors = new bytes4[](22);
        selectors[0]  = MinterGatewayHandler.updateCollateral.selector;
        selectors[1]  = MinterGatewayHandler.proposeRetrieval.selector;
        selectors[2]  = MinterGatewayHandler.proposeMint.selector;
        selectors[3]  = MinterGatewayHandler.mintM.selector;
        selectors[4]  = MinterGatewayHandler.burnM_minterMax.selector;
        selectors[5]  = MinterGatewayHandler.burnM_minterPrincipalMax.selector;
        selectors[6]  = MinterGatewayHandler.cancelMint.selector;
        selectors[7]  = MinterGatewayHandler.freezeMinter.selector;
        selectors[8]  = MinterGatewayHandler.activateMinter.selector;
        selectors[9]  = MinterGatewayHandler.deactivateMinter.selector;
        selectors[10] = MinterGatewayHandler.updateIndex.selector;
        // TTGRegistrar helper/chaos functions
        selectors[11] = MinterGatewayHandler.approveMinter.selector;
        selectors[12] = MinterGatewayHandler.disapproveMinter.selector;
        selectors[13] = MinterGatewayHandler.approveValidator.selector;
        selectors[14] = MinterGatewayHandler.disapproveValidator.selector;
        selectors[15] = MinterGatewayHandler.updateCollateralInterval.selector;
        selectors[16] = MinterGatewayHandler.updateCollateralThreshold.selector;
        selectors[17] = MinterGatewayHandler.updateMintRatio.selector;
        selectors[18] = MinterGatewayHandler.updateMintTTL.selector;
        selectors[19] = MinterGatewayHandler.updateMintFreezerTime.selector;
        selectors[20] = MinterGatewayHandler.updatePenaltyRate.selector;
        selectors[21] = MinterGatewayHandler.updateRateModel.selector;

        targetSelector(FuzzSelector({
            addr: address(_minterGatewayHandler),
            selectors: selectors
        }));

        targetContract(address(_minterGatewayHandler));
    }

    function initRegistrar() internal {
        if (_realRegistrar) {
            vm.startPrank(Registrar(_registrar.addr).standardGovernor());
            Registrar(_registrar.addr).setKey(TTGRegistrarReader.BASE_EARNER_RATE, bytes32(uint256(400)));
            Registrar(_registrar.addr).setKey(TTGRegistrarReader.BASE_MINTER_RATE, bytes32(uint256(400)));
            Registrar(_registrar.addr).setKey(TTGRegistrarReader.EARNER_RATE_MODEL, bytes32(uint256(uint160(_earnerRateModel))));
            Registrar(_registrar.addr).setKey(TTGRegistrarReader.MINTER_RATE_MODEL, bytes32(uint256(uint160(_minterRateModel))));
            Registrar(_registrar.addr).setKey(TTGRegistrarReader.UPDATE_COLLATERAL_VALIDATOR_THRESHOLD, bytes32(uint256(0)));
            Registrar(_registrar.addr).setKey(TTGRegistrarReader.UPDATE_COLLATERAL_INTERVAL, bytes32(uint256(365 days)));
            Registrar(_registrar.addr).setKey(TTGRegistrarReader.MINT_DELAY, bytes32(uint256(7 days)));
            Registrar(_registrar.addr).setKey(TTGRegistrarReader.MINT_TTL, bytes32(uint256(365 days)));
            Registrar(_registrar.addr).setKey(TTGRegistrarReader.MINT_RATIO, bytes32(uint256(9_000)));
            Registrar(_registrar.addr).setKey(TTGRegistrarReader.PENALTY_RATE, bytes32(uint256(0)));
            vm.stopPrank();
        } else {
            MockTTGRegistrar(_registrar.addr).updateConfig(TTGRegistrarReader.BASE_EARNER_RATE, 400);
            MockTTGRegistrar(_registrar.addr).updateConfig(TTGRegistrarReader.BASE_MINTER_RATE, 400);
            MockTTGRegistrar(_registrar.addr).updateConfig(TTGRegistrarReader.EARNER_RATE_MODEL, _earnerRateModel);
            MockTTGRegistrar(_registrar.addr).updateConfig(TTGRegistrarReader.MINTER_RATE_MODEL, _minterRateModel);
            if (!_integration) {
                MockRateModel(_minterRateModel).setRate(400);
                MockRateModel(_earnerRateModel).setRate(400);
            }
            MockTTGRegistrar(_registrar.addr).updateConfig(TTGRegistrarReader.UPDATE_COLLATERAL_VALIDATOR_THRESHOLD, uint256(0));
            MockTTGRegistrar(_registrar.addr).updateConfig(TTGRegistrarReader.UPDATE_COLLATERAL_INTERVAL, 365 days);
            MockTTGRegistrar(_registrar.addr).updateConfig(TTGRegistrarReader.MINT_DELAY, 7 days);
            MockTTGRegistrar(_registrar.addr).updateConfig(TTGRegistrarReader.MINT_TTL, 365 days);
            MockTTGRegistrar(_registrar.addr).updateConfig(TTGRegistrarReader.MINT_RATIO, 9_000);
            MockTTGRegistrar(_registrar.addr).updateConfig(TTGRegistrarReader.PENALTY_RATE, uint256(0));
        }

    }

    //
    // metadata invariants
    //
    function invariant_MG_M1() public leap {
        require(
            minterGateway.mToken() == _mToken.addr, "Metadata Invariant M1"
        );
    }

    // mintRatio <= 10_000% or 1_000_000 bps
    function invariant_MG_M2() public view {
        require(
            minterGateway.mintRatio() <= uint32(1_000_000), "Metadata Invariant MG_M2"
        );
    }

    //
    // balance invariants
    //
    // track collateral updates and run through all actors at the end to sum
    // and double check
    // collateral of a minter = tracked collateral - pendingRetrievals.
    // This invariant ignores whether the collateral is expired or not.
    function invariant_MG_B1() public leap {
        uint256 collateral;
        uint256 actorCount = _minterGatewayHandler.getActorsCount();

        for (uint256 i = 0; i < actorCount; i++) {
            InvariantUtils.Actor memory actor;
            (actor.addr, actor.key) = _minterGatewayHandler.actors(i);
            // collateralOf is 0 if the collateral has not been updated in time
            // so we look into the storage slot for MinterState.collateral for this invariant
            collateral += _minterGatewayHandler.rawCollateralOf(actor.addr);
            // Finding 10.3, it is not guaranteed that collateral > pendingRetrievals currently
            // collateral -= minterGateway.totalPendingCollateralRetrievalOf(actor.addr);
        }

        console.log("collateral                             ", collateral);
        console.log("_minterGatewayHandler.collateralTotal()", _minterGatewayHandler.collateralTotal());
        console.log("difference                             ", collateral > _minterGatewayHandler.collateralTotal() ? collateral - _minterGatewayHandler.collateralTotal() : _minterGatewayHandler.collateralTotal() - collateral);


        require(
            _minterGatewayHandler.collateralTotal() == collateral,
            "Balance Invariant MG_B1"
        );
    }

    // proposeRetrieval
    //   The the minterStates[minter_].totalPendingRetrievals must be:
    //   equal to sum of all pendingRetrievals
    function invariant_MG_B2() public leap {
        uint256 totalPendingRetrievals;
        uint256 actorCount = _minterGatewayHandler.getActorsCount();

        for (uint256 i = 0; i < actorCount; i++) {
            InvariantUtils.Actor memory actor;
            (actor.addr, actor.key) = _minterGatewayHandler.actors(i);
            totalPendingRetrievals += minterGateway.totalPendingCollateralRetrievalOf(actor.addr);
        }

        require(
            _minterGatewayHandler.pendingRetrievalsTotal() == totalPendingRetrievals,
            "Balance Invariant MG_B2"
        );
    }

    // sum of user balances = mintedTotal
    // this should be included in a MToken + MinterGateway invariant
    function invariant_MG_B3() public leap {
        uint256 balances;
        uint256 actorCount = _minterGatewayHandler.getActorsCount();

        for (uint256 i = 0; i < actorCount; i++) {
            InvariantUtils.Actor memory actor;
            (actor.addr, actor.key) = _minterGatewayHandler.actors(i);
            balances += _minterGatewayHandler.mTokenBalanceOf(actor.addr);
        }

        require(
            _minterGatewayHandler.mintedTotal() == balances,
            "Balance Invariant MG_B3"
        );
    }

    // sum of minted tokens <= sum of proposeMint - sum of cancelMint
    function invariant_MG_B4() public leap {
        uint256 totalMintActions = _minterGatewayHandler.mintedTotal() +  _minterGatewayHandler.cancelMintTotal() + _minterGatewayHandler.pendingMintTotal();
        require(
            _minterGatewayHandler.proposeMintTotal() == totalMintActions ,
            "Balance Invariant MG_B4"
        );
    }

    //
    // user pending retrievals should == minter totalPendingRetrievals
    //
    function invariant_MG_B5() public leap {
        uint256 actorCount = _minterGatewayHandler.getActorsCount();
        uint256 nonce = _minterGatewayHandler.currentRetrievalNonce();
        for (uint256 i = 0; i < actorCount; i++) {
            InvariantUtils.Actor memory actor;
            (actor.addr, actor.key) = _minterGatewayHandler.actors(i);
            if (minterGateway.isDeactivatedMinter(actor.addr)) {
                // TODO INVARIANT VIOLATION SKIP for Issue #69
                continue;
            }
            uint256 pendingRetrievals;
            // nonce is incremented then used, so range will be inclusive of nonce
            for(uint256 j = 0; j <= nonce; j++) {
                pendingRetrievals += minterGateway.pendingCollateralRetrievalOf(actor.addr, j);
            }
            require(
                pendingRetrievals == minterGateway.totalPendingCollateralRetrievalOf(actor.addr),
                "Balance Invariant MG_B5"
            );
        }
    }

    // minters with rawCollateral and expiry in the future collateralOf = rawCollateral - pendingRetrievals
    // minters with rawCollateral and expiry in the past   collateralOf = 0
    function invariant_MG_B6() public leap {
        uint256 actorCount = _minterGatewayHandler.getActorsCount();
        for (uint256 i = 0; i < actorCount; i++) {
            InvariantUtils.Actor memory actor;
            (actor.addr, actor.key) = _minterGatewayHandler.actors(i);
            uint256 rawCollateral   = _minterGatewayHandler.rawCollateralOf(actor.addr);
            uint256 expiry          = minterGateway.collateralExpiryTimestampOf(actor.addr);
            uint256 collateralOf    = minterGateway.collateralOf(actor.addr);
            if (block.timestamp > expiry) {
                require(
                    collateralOf == 0,
                    "Balance Invariant MG_B6"
                );
            } else {
                uint256 pendingRetrievals = minterGateway.totalPendingCollateralRetrievalOf(actor.addr);
                // because of Finding 10.3, pendingRetrievals could be greater than rawCollateral
                rawCollateral = (pendingRetrievals > rawCollateral ? 0 : rawCollateral - pendingRetrievals);
                require(
                    rawCollateral == collateralOf,
                    "Balance Invariant MG_B6"
                );
            }
        }
    }

    // pending mint proposals should be == to sum of mintProposalOf each actor
    function invariant_MG_B7() public leap {
        uint256 actorCount = _minterGatewayHandler.getActorsCount();
        uint256 totalProposals;
        for (uint256 i = 0; i < actorCount; i++) {
            InvariantUtils.Actor memory actor;
            (actor.addr, actor.key) = _minterGatewayHandler.actors(i);
            (,,,uint256 actorProposal) = minterGateway.mintProposalOf(actor.addr);
            totalProposals += actorProposal;
        }
        console.log("totalProposals:   ", totalProposals);
        console.log("pendingMintTotal: ", _minterGatewayHandler.pendingMintTotal());
        console.log("difference        ", totalProposals > _minterGatewayHandler.pendingMintTotal() ? totalProposals - _minterGatewayHandler.pendingMintTotal() : _minterGatewayHandler.pendingMintTotal() - totalProposals);
        require(
            _minterGatewayHandler.pendingMintTotal() == totalProposals,
            "Balance Invariant MG_B7"
        );
    }

    // ensure amount burned does not exceed mintedTotal
    function invariant_MG_B8() public leap {
        require(
            _minterGatewayHandler.burnMTotal() <= _minterGatewayHandler.mintedTotal(),
            "Balance Invariant MG_B8"
        );
    }

    // Functions don't exceed max gas
    function invariant_MG_G1() public leap {
        require(
            _minterGatewayHandler.gasViolations() == 0,
            "Gas Invariant MG_G1"
        );
    }

    // Free Invariant: cancel mint proposals success can't exceed total proposals
    // We are getting this for free because the minterGatewayHandler.cancelMint success
    // decreases pendingMintTotal by the mint proposal amount, so would underflow if this is violated


    // totalPendingRetrievals should not be greater than rawCollateral for an actor
    // totalRawCollateal >= totalPendingRetrievals
    // Finding 10.3, it is not guaranteed that collateral > pendingRetrievals currently
    // Unless this is change, this Invariant is not valid.
    // function invariant_MG_B#() public leap {
    //     uint256 actorCount = _minterGatewayHandler.getActorsCount();
    //     uint256 totalRawCollateral;
    //     uint256 totalPendingRetrievals;
    //     for (uint256 i = 0; i < actorCount; i++) {
    //         InvariantUtils.Actor memory actor;
    //         (actor.addr, actor.key)   = _minterGatewayHandler.actors(i);
    //         uint256 rawCollateral     = _minterGatewayHandler.rawCollateralOf(actor.addr);
    //         uint256 pendingRetrievals = minterGateway.totalPendingCollateralRetrievalOf(actor.addr);
    //         require(
    //             rawCollateral >= pendingRetrievals,
    //             "Balance Invariant B# - Actor"
    //         );
    //         totalRawCollateral += rawCollateral;
    //         totalPendingRetrievals += pendingRetrievals;
    //     }
    //     require(
    //         totalRawCollateral >= totalPendingRetrievals,
    //         "Balance Invariant B# - Sum"
    //     );
    // }

    // sum of active Minter's rawOwedM should equal principalOfTotalActiveOwedM
    // See Issue #123 for more details
    function invariant_MG_B9() public leap {
        uint256 actorCount = _minterGatewayHandler.getActorsCount();
        uint256 totalActiveMinterM;
        for (uint256 i = 0; i < actorCount; i++) {
            InvariantUtils.Actor memory actor;
            (actor.addr, actor.key)   = _minterGatewayHandler.actors(i);
            totalActiveMinterM += minterGateway.principalOfActiveOwedMOf(actor.addr);
        }
        require(
            minterGateway.principalOfTotalActiveOwedM() == totalActiveMinterM,
            "Balance Invariant B9 - Sum"
        );
    }

    //
    // proposeRetrieval tracks nonces and ensures that the nonce is
    // equal to the number stored in the minterGateway
    function invariant_MG_N1() public leap {
        require(
            _minterGatewayHandler.proposeRetrievalSuccessCount() == _minterGatewayHandler.currentRetrievalNonce(),
            "Nonce Invariant MG_N1"
        );
    }

    // MintNonce should equal the number of successful mint proposal calls
    function invariant_MG_N2() public leap {
        require(
            _minterGatewayHandler.proposeMintSuccessCount() == _minterGatewayHandler.currentMintNonce(),
            "Nonce Invariant MG_N2"
        );
    }

    // penalizedUntilTimestamp <= updateTimestamp
    function invariant_MG_T1() public leap {
        uint256 actorCount = _minterGatewayHandler.getActorsCount();
        for (uint256 i = 0; i < actorCount; i++) {
            InvariantUtils.Actor memory actor;
            (actor.addr, actor.key) = _minterGatewayHandler.actors(i);
            uint256 penalizedUntilTimestamp = _minterGatewayHandler.rawPenalizedUntilTimestamp(actor.addr);
            uint256 updateTimestamp = _minterGatewayHandler.rawUpdateTimestamp(actor.addr);
            require(
                penalizedUntilTimestamp <= updateTimestamp,
                "Timestamp Invariant MG_T1"
            );
        }
    }
}

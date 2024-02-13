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
import { BaseInvariants } from "./lib/BaseInvariants.sol";
import { BaseMZeroInvariants } from "./lib/BaseMZeroInvariants.sol";
import { InvariantUtils } from "./lib/InvariantUtils.sol";
import { DistributionVaultHandler } from "./handlers/DistributionVaultHandler.sol";

import {
    DistributionVault,
    MockERC20,
    MockEpochBasedVoteToken,
    PowerToken,
    PureEpochs,
    ZeroToken
} from "./lib/Ttg.sol";

contract DistributionVaultInvariants is BaseInvariants, BaseMZeroInvariants {
    DistributionVaultHandler public _distributionVaultHandler;

    function setUp() public virtual {

        if (!_integration) {
            vm.warp(1_663_224_162);

            zeroToken = ZeroToken(address(new MockEpochBasedVoteToken()));
            powerToken = PowerToken(address(new MockERC20()));
            distributionVault = new DistributionVault(address(zeroToken));
        }

        _distributionVaultHandler = new DistributionVaultHandler(
            address(this),
            distributionVault,
            zeroToken,
            powerToken
        );

        if (!_integration) {
            _distributionVaultHandler.init(NUM_OF_ACTORS);
        } else {
            _distributionVaultHandler.init(_actors, _receivers);
        }

        bytes4[] memory selectors = new bytes4[](3);
        selectors[0] = DistributionVaultHandler.claim.selector;
        selectors[1] = DistributionVaultHandler.claimBySig.selector;
        selectors[2] = DistributionVaultHandler.distribute.selector;

        targetSelector(
            FuzzSelector({
                addr: address(_distributionVaultHandler),
                selectors: selectors
            })
        );

        targetContract(address(_distributionVaultHandler));
    }

    //
    // metadata invariants
    //
    function invariant_DV_M1() public leap {
        require(
            distributionVault.zeroToken() == address(zeroToken),
            "Metadata Invariant DV_M1"
        );
    }

    function invariant_DV_M2() public leap {
        require(
            strcmp(distributionVault.name(), "DistributionVault"),
            "Metadata Invariant DV_M2"
        );
    }

    function invariant_DV_M3() public leap {
        require(
            strcmp(distributionVault.CLOCK_MODE(), "mode=epoch"),
            "Metadata Invariant DV_M3"
        );
    }

    function invariant_DV_M4() public leap {
        require(
            distributionVault.clock() == PureEpochs.currentEpoch(),
            "Metadata Invariant DV_M4"
        );
    }

    // Functions don't exceed max gas
    function invariant_DV_G1() public leap {
        require(
            _distributionVaultHandler.gasViolations() == 0,
            "Gas Invariant DV_G1"
        );
    }

    //
    // balance invariants
    //

    // all successfully claimed epochs inclusively should have claimable balance
    // of 0
    function invariant_DV_B1() public leap {
        require(
            _distributionVaultHandler.remainingClaimable() == 0,
            "Balance Invariant DV_B1"
        );
    }

    // all successfully claimed epochs inclusively be marked as claimed
    function invariant_DV_B2() public leap {
        require(
            _distributionVaultHandler.remainingHasClaimed() == 0,
            "Balance Invariant DV_B2"
        );
    }

    function invariant_DV_B3() public leap {
        require(
            _distributionVaultHandler.totalClaimed() <= _distributionVaultHandler.totalDistributed(),
            "Balance Invariant DV_B3"
        );
    }

    // BaseToken balance of all the actors should equal totalClaimed
    // TODO this will not work with the mock token
    // function invariant_DV_B3() public leap {
    //     uint256 totalClaimed = _distributionVaultHandler.totalClaimed();
    //     uint256 totalBalance;

    //     for (uint256 i = 0; i < NUM_OF_ACTORS; i++) {
    //         InvariantUtils.Actor memory actor;
    //         (actor.addr, actor.key) = _distributionVaultHandler.actors(i);
    //         uint256 balance = zeroToken.balanceOf(actor.addr);
    //         totalBalance += balance;
    //     }

    //     require(totalClaimed == totalBalance, "Balance Invariant B3");
    // }

    // TODO possible integration invariant: the only way the distributionVault's
    // Token Balance for Token1 decreases is if it is claimed.  If the token balance
    // decreases below lastTokenBalance, then the distribute will fail on underflow.
}

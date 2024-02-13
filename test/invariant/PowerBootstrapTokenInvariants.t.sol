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

import { BaseInvariants } from "./lib/BaseInvariants.sol";
// import "forge-std/console.sol";
import { InvariantUtils } from "./lib/InvariantUtils.sol";
import { PowerBootstrapToken } from "./lib/Ttg.sol";
import { PowerBootstrapTokenHandler } from "./handlers/PowerBootstrapTokenHandler.sol";

contract PowerBootstrapTokenInvariants is BaseInvariants {
    PowerBootstrapToken public powerBootstrapToken;
    PowerBootstrapTokenHandler public _powerBootstrapTokenHandler;

    function setUp() public virtual {

        _powerBootstrapTokenHandler = new PowerBootstrapTokenHandler(
            address(this)
        );

        powerBootstrapToken = _powerBootstrapTokenHandler.init(NUM_OF_ACTORS);

        bytes4[] memory selectors = new bytes4[](2);
        // note: these are only view functions, but are needed to restrict the selectors
        selectors[0]  = PowerBootstrapTokenHandler.pastBalanceOf.selector;
        selectors[1]  = PowerBootstrapTokenHandler.pastTotalSupply.selector;


        targetSelector(FuzzSelector({
            addr: address(_powerBootstrapTokenHandler),
            selectors: selectors
        }));

        targetContract(address(_powerBootstrapTokenHandler));
    }

    //
    // balance invariants
    //
    function invariant_PB_B1() public leap {
        uint256 balance = 0;
        uint256 actorCount = _powerBootstrapTokenHandler.getActorsCount();

        for (uint256 i = 0; i < actorCount; i++) {
            InvariantUtils.Actor memory actor;
            (actor.addr, actor.key) = _powerBootstrapTokenHandler.actors(i);
            balance += powerBootstrapToken.pastBalanceOf(actor.addr, 0);
        }

        require(
            balance == powerBootstrapToken.pastTotalSupply(0), "Balance Invariant PB_B1"
        );
    }

    // Functions don't exceed max gas
    function invariant_PB_G1() public leap {
        require(
            _powerBootstrapTokenHandler.gasViolations() == 0,
            "Gas Invariant PB_G1"
        );
    }
}

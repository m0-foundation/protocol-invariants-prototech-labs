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

import "./base/BaseHandler.sol";
import { PowerBootstrapToken } from "../lib/Ttg.sol";

contract PowerBootstrapTokenHandler is BaseHandler {
    PowerBootstrapToken public powerBootstrapToken;

    constructor(
        address _testContract
    ) BaseHandler(_testContract) {}

    function init(
        uint256 _numOfActors
    ) external returns (PowerBootstrapToken) {

        address[] memory guys = new address[](_numOfActors + 1);
        uint256[] memory amounts = new uint256[](_numOfActors + 1);

        addActors(_numOfActors);

        for(uint256 i = 0; i < _numOfActors; i++) {
            guys[i] = actors[i].addr;
            amounts[i] = 1e18;
        }

        addActor(address(0), "zero");
        guys[_numOfActors - 1] = actors[_numOfActors - 1].addr;
        amounts[_numOfActors - 1] = 0;

        powerBootstrapToken = new PowerBootstrapToken(guys, amounts);

        addActor(address(powerBootstrapToken), "PowerBootstrapToken");

        validateActors();

        return powerBootstrapToken;
    }

    //
    // View functions
    //
    // including these so we can have the invariant setup for PowerBootstrapToken
    // they are just pass through view functions but without them the invariants
    //
    function pastBalanceOf(
        uint256 _actorIndex
    ) public leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        powerBootstrapToken.pastBalanceOf(actor.addr, 0);
    }

    function pastTotalSupply(
        uint256 _actorIndex
    ) public leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        powerBootstrapToken.pastTotalSupply(0);
    }
}

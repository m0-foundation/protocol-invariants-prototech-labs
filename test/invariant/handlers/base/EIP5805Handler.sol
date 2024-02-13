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

import "./BaseHandler.sol";

abstract contract EIP5805Handler is BaseHandler {
    // EIP5805 state
    mapping(uint256 => mapping(address => bool)) public pastVotesCached;
    mapping(uint256 => mapping(address => uint256)) public pastVotesCache;
    mapping(uint256 => mapping(address => bool)) public pastBalancesCached;
    mapping(uint256 => mapping(address => uint256)) public pastBalancesCache;
    mapping(uint256 => mapping(address => bool)) public pastDelegatesCached;
    mapping(uint256 => mapping(address => address)) public pastDelegatesCache;

    constructor() {}

    function pastVotesAreConst(
        IToken _token,
        uint256 _epoch
    ) external returns (bool) {
        for(uint256 i = 0; i < actors.length; i++) {
            if (pastVotesCached[_epoch][actors[i].addr]) {
                if (pastVotesCache[_epoch][actors[i].addr] !=
                    _token.getPastVotes(actors[i].addr, _epoch)) {
                    return false;
                }
            } else {
                pastVotesCached[_epoch][actors[i].addr] = true;
                pastVotesCache[_epoch][actors[i].addr] =
                    _token.getPastVotes(actors[i].addr, _epoch);
            }
        }

        return true;
    }

    function pastBalancesAreConst(
        IToken _token,
        uint256 _epoch
    ) external returns (bool) {
        for(uint256 i = 0; i < actors.length; i++) {
            if (pastBalancesCached[_epoch][actors[i].addr]) {
                if (pastBalancesCache[_epoch][actors[i].addr] !=
                    _token.pastBalanceOf(actors[i].addr, _epoch)) {
                    return false;
                }
            } else {
                pastBalancesCached[_epoch][actors[i].addr] = true;
                pastBalancesCache[_epoch][actors[i].addr] =
                    _token.pastBalanceOf(actors[i].addr, _epoch);
            }
        }

        return true;
    }

    function pastDelegatesAreConst(
        IToken _token,
        uint256 _epoch
    ) external returns (bool) {
        for(uint256 i = 0; i < actors.length; i++) {
            if (pastDelegatesCached[_epoch][actors[i].addr]) {
                if (pastDelegatesCache[_epoch][actors[i].addr] !=
                    _token.pastDelegates(actors[i].addr, _epoch)) {
                    return false;
                }
            } else {
                pastDelegatesCached[_epoch][actors[i].addr] = true;
                pastDelegatesCache[_epoch][actors[i].addr] =
                    _token.pastDelegates(actors[i].addr, _epoch);
            }
        }

        return true;
    }
}

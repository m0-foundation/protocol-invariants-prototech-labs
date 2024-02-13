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

abstract contract EIP3009Handler is BaseHandler {
    // to determine what nonce states have been burned for 3009
    mapping(address => mapping(bytes32 => bool)) public nonceState;

    // to determine if allowance has changed for 3009
    mapping(address account => mapping(address spender => uint256 allowance)) public allowanceBefore;

    // EIP3009 violation counters
    uint256 public EIP3009AllowanceViolationCount;
    uint256 public EIP3009ValidViolationCount;
    uint256 public nonceViolation3009Count;

    constructor() {}

    function snapAllowanceValues(IToken _token) public {
        for(uint256 i = 0; i < actors.length; i++) {
            for(uint256 j = 0; j < actors.length; j++) {
                allowanceBefore[actors[i].addr][actors[j].addr] =
                    _token.allowance(actors[i].addr, actors[j].addr);
            }
        }
    }

    function allowanceDiff(IToken _token) public view returns (bool) {
        for(uint256 i = 0; i < actors.length; i++) {
            for(uint256 j = 0; j < actors.length; j++) {
                if(allowanceBefore[actors[i].addr][actors[j].addr] !=
                    _token.allowance(actors[i].addr, actors[j].addr)) {
                    return true;
                }
            }
        }

        return false;
    }
}

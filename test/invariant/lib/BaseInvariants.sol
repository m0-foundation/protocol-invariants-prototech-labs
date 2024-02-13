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

pragma solidity 0.8.23;

import { Test, console, console2 } from "forge-std/Test.sol";
import { InvariantUtils } from "../lib/InvariantUtils.sol";

contract BaseInvariants is Test {
    InvariantUtils.Actor[] internal _actors;
    InvariantUtils.Actor[] internal _receivers;

    uint256 public currentBlock = 15_537_393;           // start at the merge
    uint256 public setBlocks;
    uint256[] public blocks;

    uint256 public currentTimestamp = 1_663_224_162;    // start at the merge
    uint256 public setTimestamps;
    uint256[] public timestamps;

    uint256 public NUM_OF_ACTORS = uint256(
        vm.envOr("NUM_OF_ACTORS", uint256(10))
    );

    constructor() {
        vm.warp(1_663_224_162);
    }

    modifier leap {
        vm.warp(currentTimestamp);
        vm.roll(currentBlock);
        _;
    }

    function strcmp(string memory a, string memory b) public pure returns (bool) {
        return (keccak256(abi.encodePacked((a))) == keccak256(abi.encodePacked((b))));
    }

    function setCurrentTimestamp(uint256 _currentTimestamp) external {
        timestamps.push(_currentTimestamp);
        setTimestamps++;
        currentTimestamp = _currentTimestamp;
    }

    function setCurrentBlock(uint256 _currentBlock) external {
        blocks.push(_currentBlock);
        setBlocks++;
        currentBlock = _currentBlock;
    }
}

// SPDX-License-Identifier: UNLICENSED

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

pragma solidity ^0.8.23;

import { ZeroGovernorInvariants } from "../ZeroGovernorInvariants.t.sol";

contract ZeroGovernorRegressionTests is ZeroGovernorInvariants {

    function setUp() public override {
        super.setUp();
    }

    function _setMaxLeap(uint256 maxLeap) internal {
        _zeroGovernorHandler.setMaxLeap(maxLeap);
    }
}

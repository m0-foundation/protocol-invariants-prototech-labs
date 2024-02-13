pragma solidity ^0.8.23;

import { StandardGovernorInvariants } from "../StandardGovernorInvariants.t.sol";

contract StandardGovernorRegressionTests is StandardGovernorInvariants {

    function setUp() public override {
        super.setUp();
    }

    function _setMaxLeap(uint256 maxLeap) internal {
        _standardGovernorHandler.setMaxLeap(maxLeap);
    }
}

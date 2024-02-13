pragma solidity ^0.8.23;

import { EmergencyGovernorInvariants } from "../EmergencyGovernorInvariants.t.sol";

contract EmergencyGovernorRegressionTests is EmergencyGovernorInvariants {

    function setUp() public override {
        super.setUp();
    }

    function _setMaxLeap(uint256 maxLeap) internal {
        _emergencyGovernorHandler.setMaxLeap(maxLeap);
    }
}

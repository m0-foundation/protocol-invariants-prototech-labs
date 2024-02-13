pragma solidity ^0.8.23;

import { DistributionVaultInvariants } from "../DistributionVaultInvariants.t.sol";

contract DistributionVaultRegressionTests is DistributionVaultInvariants {

    function setUp() public override {
        super.setUp();
    }

    function _setMaxLeap(uint256 maxLeap) internal {
        _distributionVaultHandler.setMaxLeap(maxLeap);
    }

}

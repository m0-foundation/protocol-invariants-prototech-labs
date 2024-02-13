pragma solidity ^0.8.23;

import { PowerBootstrapTokenInvariants } from "../PowerBootstrapTokenInvariants.t.sol";
// solhint-disable-next-line no-console, no-global-import
import "forge-std/console.sol";

contract PowerBootstrapTokenRegressionTests is PowerBootstrapTokenInvariants {
    function setUp() public override {
        super.setUp();
    }

    function _setMaxLeap(uint256 maxLeap) internal {
        _powerBootstrapTokenHandler.setMaxLeap(maxLeap);
    }

}

pragma solidity ^0.8.23;

import { RegistrarInvariants } from "../RegistrarInvariants.t.sol";
// solhint-disable-next-line no-console, no-global-import
import "forge-std/console.sol";

contract RegistrarRegressionTests is RegistrarInvariants {
    function setUp() public override {
        super.setUp();
    }

    function _setMaxLeap(uint256 maxLeap) internal {
        _registrarHandler.setMaxLeap(maxLeap);
    }
}

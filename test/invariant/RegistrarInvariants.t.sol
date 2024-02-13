
pragma solidity ^0.8.23;

// solhint-disable-next-line no-console, no-global-import
import "forge-std/console.sol";
import { BaseInvariants } from "./lib/BaseInvariants.sol";
import { BaseMZeroInvariants } from "./lib/BaseMZeroInvariants.sol";
import { InvariantUtils } from "./lib/InvariantUtils.sol";
import { RegistrarHandler } from "./handlers/RegistrarHandler.sol";

import {
   MockZeroGovernor,
   MockEmergencyGovernorDeployer,
   MockStandardGovernorDeployer,
   MockPowerTokenDeployer,
   Registrar
} from "./lib/Ttg.sol";

contract RegistrarInvariants is BaseInvariants, BaseMZeroInvariants {

    RegistrarHandler public _registrarHandler;

    function setUp() public virtual {
        if (!_integration) {
            _mockEmergencyGovernorDeployer = new MockEmergencyGovernorDeployer();
            _mockPowerTokenDeployer = new MockPowerTokenDeployer();
            _mockStandardGovernorDeployer = new MockStandardGovernorDeployer();
            _mockZeroGovernor = new MockZeroGovernor();

            _mockEmergencyGovernorDeployer.setLastDeploy(_emergencyGovernor.addr);

            _mockPowerTokenDeployer.setLastDeploy(_powerToken.addr);

            _mockStandardGovernorDeployer.setLastDeploy(_standardGovernor.addr);
            _mockStandardGovernorDeployer.setVault(_distributionVault.addr);

            _mockZeroGovernor.setEmergencyGovernorDeployer(address(_mockEmergencyGovernorDeployer));
            _mockZeroGovernor.setPowerTokenDeployer(address(_mockPowerTokenDeployer));
            _mockZeroGovernor.setStandardGovernorDeployer(address(_mockStandardGovernorDeployer));
            _mockZeroGovernor.setVoteToken(_zeroToken.addr);
            _zeroGovernor.addr = address(_mockZeroGovernor);

            registrar = createRegistrar(_zeroGovernor.addr);
        }

        _registrarHandler = new RegistrarHandler(
            address(this),
            registrar
        );

        if (!_integration) {
            _registrarHandler.init();
        } else {
            _registrarHandler.init(_actors, _receivers);
        }

        // add all testable functions
        bytes4[] memory selectors = new bytes4[](3);
        selectors[0]  = RegistrarHandler.addToList.selector;
        selectors[1]  = RegistrarHandler.removeFromList.selector;
        selectors[2]  = RegistrarHandler.setKey.selector;

        targetSelector(FuzzSelector({
            addr: address(_registrarHandler),
            selectors: selectors
        }));

        targetContract(address(_registrarHandler));
    }

    // Create a new registrar with an existing ZeroGovernor
    function createRegistrar(address zeroGovernor_) public returns (Registrar) {
        return new Registrar(zeroGovernor_);
    }

    //
    // metadata invariants
    //
    function invariant_R_M1() public leap {
        require(
            registrar.zeroGovernor() == _zeroGovernor.addr,
            "Metadata Invariant R_M1"
        );
    }

    function invariant_R_M2() public leap {
        bytes32[] memory keys = _registrarHandler.getKeys();
        bytes32[] memory values = _registrarHandler.getValues();
        uint256 klen = keys.length;
        require(klen == values.length, "RegistrarHandler Error");

        for (uint256 i = 0; i < klen; i++) {

            require(registrar.get(keys[i]) == values[i] ||
                    registrar.listContains(keys[i], address(uint160(uint256(values[i])))),
                    "Metadata Invariant R_M2");
        }
    }

    //
    // Authorization Invariants
    //

    // Only Standard or Emergency Governor
    function invariant_R_Z1() public leap {
        require(
            _registrarHandler.notStandardOrEmergencyGovernorViolationCount() == 0,
            "Authorization Invariant R_Z1"
        );
    }

    // Functions don't exceed max gas
    function invariant_R_G1() public leap {
        require(
            _registrarHandler.gasViolations() == 0,
            "Gas Invariant R_G1"
        );
    }
}

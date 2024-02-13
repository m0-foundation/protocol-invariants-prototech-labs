pragma solidity ^0.8.23;

// solhint-disable-next-line no-console, no-global-import
import "forge-std/console.sol";
import { BaseMZeroInvariants } from "./lib/BaseMZeroInvariants.sol";
import { TTGInvariants } from "./TTGInvariants.t.sol";
import { ProtocolInvariants } from "./ProtocolInvariants.t.sol";
import { InvariantUtils, IToken } from "./lib/InvariantUtils.sol";

contract MZeroInvariants is
    BaseMZeroInvariants,
    TTGInvariants,
    ProtocolInvariants
{
    function setUp() public virtual override(
        TTGInvariants,
        ProtocolInvariants
    ) {
        InvariantUtils.Actor memory guy;

        vm.warp(1_663_224_162);

        for (uint256 i = 0; i < NUM_OF_ACTORS; i++) {
            (guy.addr, guy.key) = makeAddrAndKey(
                string(abi.encodePacked("Actor", vm.toString(i)))
            );
            _initialPowerAccounts.push(guy.addr);
            _initialPowerBalances.push(1e6);
            _initialZeroAccounts.push(guy.addr);
            _initialZeroBalances.push(1e12);
            _actors.push(guy);
            _receivers.push(guy);
        }

        // deployer actor
        _initialPowerAccounts.push(deployer.addr);
        _initialPowerBalances.push(0);
        _initialZeroAccounts.push(deployer.addr);
        _initialZeroBalances.push(0);
        _actors.push(deployer);
        _receivers.push(deployer);

        // zero actor
        _initialPowerAccounts.push(_zero.addr);
        _initialPowerBalances.push(0);
        _initialZeroAccounts.push(_zero.addr);
        _initialZeroBalances.push(0);
        _receivers.push(_zero);

        // flag to the other modules that we're running in integration mode
        _integration = true;

        TTGInvariants.setUp();
        ProtocolInvariants.setUp();

        _emergencyGovernorHandler._initRateModels(address(registrar), address(minterGateway));
        _standardGovernorHandler._initRateModels(address(registrar), address(minterGateway));
    }

    // Invariant harness sanity check
    function invariant_MZ_T1() public leap {
        uint256 timestamp = block.timestamp;
        require(timestamp == currentTimestamp, "Invariant MZ_T1");
        require(timestamp == _distributionVaultHandler.timestamp(), "Invariant MZ_T1_DV");
        require(timestamp == _zeroTokenHandler.timestamp(), "Invariant MZ_T1_ZT");
        require(timestamp == _powerTokenHandler.timestamp(), "Invariant MZ_T1_PT");
        //require(timestamp == _registrarHandler.timestamp(), "Invariant MZ_T1_R");
        //require(timestamp == _mTokenHandler.timestamp(), "Invariant MZ_T1_M");
        //require(timestamp == _standardGovernorHandler.timestamp(), "Invariant MZ_T1_SG");
        //require(timestamp == _emergencyGovernorHandler.timestamp(), "Invariant MZ_T1_EG");
        //require(timestamp == _zeroGovernorHandler.timestamp(), "Invariant MZ_T1_ZG");
        //require(timestamp == _minterGatewayHandler.timestamp(), "Invariant MZ_T1_MG");
    }
}

pragma solidity ^0.8.23;

// solhint-disable-next-line no-console, no-global-import
import "forge-std/console.sol";

import { BaseMZeroInvariants } from "./lib/BaseMZeroInvariants.sol";
import { MinterGatewayInvariants } from "./MinterGatewayInvariants.t.sol";
import { MTokenInvariants } from "./MTokenInvariants.t.sol";
import { InvariantUtils } from "./lib/InvariantUtils.sol";

import {
    DeployBase,
    MinterGateway,
    MockTTGRegistrar,
    MToken
} from "./lib/Protocol.sol";

contract ProtocolInvariants is
    BaseMZeroInvariants,
    MinterGatewayInvariants,
    MTokenInvariants
{

    DeployBase public deployProtocol;

    function setUp() public virtual override(
        MinterGatewayInvariants,
        MTokenInvariants
    ) {
        InvariantUtils.Actor memory guy;

        // If not called from MZeroInvariants, we need to set up the actors
        if (_actors.length == 0) {
            vm.warp(1_663_224_162);

            for (uint256 i = 0; i < NUM_OF_ACTORS; i++) {
                (guy.addr, guy.key) = makeAddrAndKey(
                    string(abi.encodePacked("Actor", vm.toString(i)))
                );
                _actors.push(guy);
                _receivers.push(guy);
            }

            // deployer actor
            _actors.push(deployer);
            _receivers.push(deployer);

            // zero actor
            _receivers.push(_zero);
        }

        // registrar
        if (address(registrar) == address(0)) {
            // We still need to mock registrar in Protocol unless it's already
            // been deployed in the MZeroInvariants
            _mockTTGRegistrar = new MockTTGRegistrar();
            _mockTTGRegistrar.setVault(_distributionVault.addr);
            _registrar.addr = address(_mockTTGRegistrar);
            _receivers.push(_registrar);
        }

        deployProtocol = new DeployBase();
        (_minterGateway.addr, _minterRateModel, _earnerRateModel) = deployProtocol.deploy(
            deployer.addr,
            vm.getNonce(deployer.addr),
            _registrar.addr
        );

        // MinterGateway
        minterGateway = MinterGateway(_minterGateway.addr);
        _receivers.push(_minterGateway);

        // MToken
        mToken = MToken(minterGateway.mToken());
        _mToken.addr = address(mToken);
        _receivers.push(_mToken);

        // flag to the other modules that we're running in integration mode
        _integration = true;

        MinterGatewayInvariants.setUp();
        MTokenInvariants.setUp();
    }

    // Invariant harness sanity check
    function invariant_protocol_T1() public leap {
        uint256 timestamp = block.timestamp;
        require(timestamp == currentTimestamp, "Invariant PROT_T1");
        require(timestamp == _mTokenHandler.timestamp(), "Invariant PROT_T1_M");
        require(timestamp == _minterGatewayHandler.timestamp(), "Invariant PROT_T1_MG");
    }

    // when minterGateway.latestUpdateTimestamp() == block.timestamp excessOwedM should be 0
    // This has to be in Protocol to have a real MToken as the Mock does not handle totalSupply correctly
    function invariant_protocol_T2() public leap {
        if (minterGateway.latestUpdateTimestamp() == block.timestamp) {
            require(
                minterGateway.excessOwedM() == 0,
                "Protocol Invariant PROT_T2"
            );
        }
    }

    // ensure updateIndex is always in sync
    function invariant_protocol_S1() public leap {
        // when MinterGateway.updateIndex() is called, it should always call
        // MToken.updateIndex().  However, it is possible that MToken.updateIndex()
        // gets called without MinterGateway.updateIndex() being called.
        if (minterGateway.latestUpdateTimestamp() == block.timestamp) {
            require(minterGateway.latestUpdateTimestamp() == mToken.latestUpdateTimestamp(), "Sync Invariant PROT_S1");
        }
    }

    // MToken.totalSupply() = sum(MinterGateway.mintM() calls)
    // function invariant_protocol_B1() public leap {
    //     // we want the raw number not the number adjusted for currentIndex
    //     uint256 totalSupply = mToken.principalOfTotalEarningSupply() + mToken.totalNonEarningSupply();
    //     // we seed users with MToken in the mTokenHandler
    //     // this is not accouned for in the MinterGateway
    //     // so we need to add it to the sumMintM for the invariant to be correct
    //     uint256 sumMintM = _minterGatewayHandler.mintedTotal() + _mTokenHandler.startingMTokenSupply();
    //     require(totalSupply == sumMintM, "Invariant PROT_B1");
    // }

    // // Sum of MinterGateway user's inactive and active OwedM >= MToken.totalSupply()
    // // Greater than because of fees potentially applied in MinterGateway
    // function invariant_protocol_B2() public leap {
    //     // we seed users with MToken in the mTokenHandler
    //     // this is not accouned for in the MinterGateway
    //     // so we need to add it to the sumOwedM for the invariant to be correct
    //     uint256 sumOwedM = _mTokenHandler.startingMTokenSupply();
    //     for (uint256 i = 0; i < _actors.length; i++) {
    //         sumOwedM += minterGateway.principalOfActiveOwedMOf(_actors[i].addr);
    //         sumOwedM += minterGateway.inactiveOwedMOf(_actors[i].addr);
    //     }
    //     // we want the raw number not the number adjusted for currentIndex
    //     uint256 totalSupply = mToken.principalOfTotalEarningSupply() + mToken.totalNonEarningSupply();
    //     require(sumOwedM >= totalSupply, "Invariant PROT_B2");
    // }

}

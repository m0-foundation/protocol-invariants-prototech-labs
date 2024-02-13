
pragma solidity ^0.8.23;

// solhint-disable-next-line no-console, no-global-import
import "forge-std/console.sol";
import { BaseInvariants } from "./lib/BaseInvariants.sol";
import { BaseMZeroInvariants } from "./lib/BaseMZeroInvariants.sol";
import { InvariantUtils } from "./lib/InvariantUtils.sol";
import { MTokenHandler } from "./handlers/MTokenHandler.sol";

import {
    ContinuousIndexingMath,
    MockRateModel,
    MockTTGRegistrar,
    MToken,
    TTGRegistrarReader
} from "./lib/Protocol.sol";

contract MTokenInvariants is BaseInvariants, BaseMZeroInvariants {
    MTokenHandler public _mTokenHandler;

    uint32 internal _earnerRate = ContinuousIndexingMath.BPS_SCALED_ONE / 10; // 10% APY

    function setUp() public virtual {
        if (!_integration) {
            MockRateModel(_earnerRateModel).setRate(_earnerRate);

            // registrar
            _mockTTGRegistrar = new MockTTGRegistrar();
            _mockTTGRegistrar.updateConfig(
                TTGRegistrarReader.EARNER_RATE_MODEL,
                address(_earnerRateModel)
            );
            _registrar.addr = address(_mockTTGRegistrar);

            mToken = new MToken(_registrar.addr, _minterGateway.addr);
        }

        _mTokenHandler = new MTokenHandler(
            address(this),
            mToken,
            _minterGateway,
            _registrar
        );

        if (!_integration) {
            _mTokenHandler.init(NUM_OF_ACTORS);
        } else {
            _mTokenHandler.init(_actors, _receivers);
        }

        bytes4[] memory selectors = new bytes4[](27);
        selectors[0]  = MTokenHandler.approve.selector;
        selectors[1]  = MTokenHandler.transfer.selector;
        selectors[2]  = MTokenHandler.transferFrom.selector;
        selectors[3]  = MTokenHandler.transferWithAuthorization.selector;
        selectors[4]  = MTokenHandler.transferWithAuthorizationWithSignature.selector;
        selectors[5]  = MTokenHandler.transferWithAuthorizationWithVS.selector;
        selectors[6]  = MTokenHandler.receiveWithAuthorization.selector;
        selectors[7]  = MTokenHandler.receiveWithAuthorizationWithSignature.selector;
        selectors[8]  = MTokenHandler.receiveWithAuthorizationWithVS.selector;
        selectors[9]  = MTokenHandler.cancelAuthorization.selector;
        selectors[10] = MTokenHandler.cancelAuthorizationWithSignature.selector;
        selectors[11] = MTokenHandler.cancelAuthorizationWithVS.selector;
        selectors[12] = MTokenHandler.permit.selector;
        selectors[13] = MTokenHandler.permitWithSignature.selector;
        selectors[14] = MTokenHandler.updateIndex.selector;
        selectors[15] = MTokenHandler.mint.selector;
        selectors[16] = MTokenHandler.burn.selector;
        selectors[17] = MTokenHandler.startEarning.selector;
        selectors[18] = MTokenHandler.startEarningOnBehalfOf.selector;
        selectors[19] = MTokenHandler.stopEarning.selector;
        selectors[20] = MTokenHandler.stopEarningOnBehalfOf.selector;
        selectors[21] = MTokenHandler.allowEarningOnBehalf.selector;
        selectors[22] = MTokenHandler.disallowEarningOnBehalf.selector;
        // TTGRegistrar helper/chaos functions
        selectors[23] = MTokenHandler.updateEarnerRateModel.selector;
        selectors[24] = MTokenHandler.updateIsEarnersListIgnored.selector;
        selectors[25] = MTokenHandler.approveEarner.selector;
        selectors[26] = MTokenHandler.disapproveEarner.selector;

        targetSelector(FuzzSelector({
            addr: address(_mTokenHandler),
            selectors: selectors
        }));

        targetContract(address(_mTokenHandler));
    }

    //
    // metadata invariants
    //
    function invariant_M_M1() public leap {
        require(
            mToken.decimals() == 6,
            "Metadata Invariant M_M1"
        );
    }

    function invariant_M_M2() public leap {
        require(
            mToken.ttgRegistrar() == _registrar.addr,
            "Metadata Invariant M_M2"
        );
    }

    function invariant_M_M3() public leap {
        require(
            mToken.minterGateway() == _minterGateway.addr,
            "Metadata Invariant M_M3"
        );
    }

    // Functions don't exceed max gas
    function invariant_M_G1() public leap {
        require(
            _mTokenHandler.gasViolations() == 0,
            "Gas Invariant M_G1"
        );
    }

    //
    // balance invariants
    //

    // invariant_M_B1:
    //      mToken.totalSupply() == mToken.totalEarningSupply() + mToken.totalNonEarningSupply()
    function invariant_M_B1() public leap {
        require(
            mToken.totalSupply() == mToken.totalEarningSupply() + mToken.totalNonEarningSupply(),
            "Balance Invariant M_B1"
        );
    }

    // invariant_M_B2_B3_B4:
    //      This is a helper function to make the invariant_M_B2, invariant_M_B3,
    //      and invariant_M_B4 functions more efficient.
    function invariant_M_B2_B3_B4() public leap {
        uint256 earners;
        uint256 balance;
        uint256 earnerBalance;
        uint256 nonEarnerBalance;
        uint256 actorCount = _mTokenHandler.getActorsCount();

        for (uint256 i = 0; i < actorCount; i++) {
            InvariantUtils.Actor memory actor;
            (actor.addr, actor.key) = _mTokenHandler.actors(i);
            balance += mToken.balanceOf(actor.addr);
            // keep track of earners to adjust for 1 wei rounding errors
            if (mToken.isEarning(actor.addr)) {
                earners++;
                earnerBalance += mToken.balanceOf(actor.addr);
            } else {
                nonEarnerBalance += mToken.balanceOf(actor.addr);
            }
        }

        // invariant_M_B2:
        _invariant_M_B2(mToken.totalSupply(), earners, balance);

        // invariant_M_B3:
        _invariant_M_B3(mToken.totalNonEarningSupply(), nonEarnerBalance);

        // invariant_M_B4:
        _invariant_M_B4(mToken.totalEarningSupply(), earners, earnerBalance);
    }

    // invariant_M_B2:
    //      The sum of all user's balanceOf() >= (mToken.totalSupply() - sum of all earners)
    //      but less than or equal to mToken.totalSupply()
    function _invariant_M_B2(
        uint256 _totalSupply,
        uint256 _earners,
        uint256 _balance
    ) pure internal {
        uint256 _supply = (_totalSupply >= _earners) ?
            (_totalSupply - _earners) : 0;

        require(
            _balance >= _supply && _balance <= _totalSupply,
            "Balance Invariant M_B2"
        );
    }

    // invariant_M_B3:
    //      The sum of all mToken.balanceOf(account) for non earners to equal
    //      mToken.totalNonEarningSupply()
    function _invariant_M_B3(uint256 _totalNonEarningSupply, uint256 _balance) pure internal {
        require(_balance == _totalNonEarningSupply, "Balance Invariant M_B3");
    }

    // invariant_M_B4:
    //      The sum of all mToken.balanceOf(account) for earners is equal to
    //      (mToken.totalEarningSupply() - sum of all earners) but less than or
    //      equal to mToken.totalEarningSupply()
    function _invariant_M_B4(
        uint256 _totalEarningSupply,
        uint256 _earners,
        uint256 _balance
    ) pure internal {
        uint256 _supply = (_totalEarningSupply >= _earners) ?
            (_totalEarningSupply - _earners) : 0;

        require(
            _balance >= _supply && _balance <= _totalEarningSupply,
            "Balance Invariant M_B4"
        );
    }

    //
    // permission invariants
    //

    // invariant_M_P1:
    //      Only the minterGateway can mint
    function invariant_M_P1() public leap {
        require(
            _mTokenHandler.minterGatewayViolationCount() == 0,
            "Auth Invariant M_P1"
        );
    }

    //
    // allowance invariants
    //

    // invariant_M_A1:
    //      Only the minterGateway can mint
    function invariant_M_A1() public leap {
        require(
            _mTokenHandler.maxAllowanceViolationCount() == 0,
            "Allowance Invariant M_A1"
        );
    }

    function invariant_M_A2() public leap {
        require(
            _mTokenHandler.spendAllowanceViolationCount() == 0,
            "Allowance Invariant M_A2"
        );
    }

    function invariant_M_A3() public leap {
        require(
            _mTokenHandler.invalidNonce2612Count() == 0,
            "Allowance Invariant M_A3"
        );
    }

    //
    // Authorization Invariants
    //
    function invariant_M_Z1() public leap {
        require(
            _mTokenHandler.nonceViolation3009Count() == 0,
            "Authorization Invariant M_Z1"
        );
    }

    function invariant_M_Z2() public leap {
        require(
            _mTokenHandler.EIP3009ValidViolationCount() == 0,
            "Authorization Invariant M_Z2"
        );
    }

    function invariant_M_Z3() public leap {
        require(
            _mTokenHandler.EIP3009AllowanceViolationCount() == 0,
            "Authorization Invariant M_Z3"
        );
    }

    // TODO: add address(0) invariant checks if issue 64 requires changes
}

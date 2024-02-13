
pragma solidity ^0.8.23;

// solhint-disable-next-line no-console, no-global-import
import "forge-std/console.sol";

import { BaseInvariants } from "./lib/BaseInvariants.sol";
import { BaseMZeroInvariants } from "./lib/BaseMZeroInvariants.sol";
import { InvariantUtils, IToken } from "./lib/InvariantUtils.sol";
import { ZeroToken, StandardGovernorDeployer } from "./lib/Ttg.sol";
import { ZeroTokenHandler } from "./handlers/ZeroTokenHandler.sol";

contract ZeroTokenInvariants is BaseInvariants, BaseMZeroInvariants {
    ZeroTokenHandler internal _zeroTokenHandler;

    function setUp() public virtual {
        StandardGovernorDeployer _deployer;
        InvariantUtils.Actor memory guy;

        if (!_integration) {
            vm.warp(1_663_224_162);

            for (uint256 i = 0; i < NUM_OF_ACTORS; i++) {
                (guy.addr, guy.key) = makeAddrAndKey(
                    string(abi.encodePacked("Actor", vm.toString(i)))
                );
                _initialZeroAccounts.push(guy.addr);
                _initialZeroBalances.push(1e12);
                _actors.push(guy);
                _receivers.push(guy);
            }

            // zero actor
            (guy.addr, guy.key) = makeAddrAndKey("zero");
            guy.addr = address(0);
            _initialZeroAccounts.push(guy.addr);
            _initialZeroBalances.push(0);
            _receivers.push(guy);

            // deployer
            _deployer = new StandardGovernorDeployer(
                _zeroGovernor.addr,
                _registrar.addr,
                _distributionVault.addr,
                _zeroToken.addr
            );
            vm.prank(_zeroGovernor.addr);
            _deployer.deploy(
                makeAddr("powerToken"),
                makeAddr("emergencyGovernor"),
                makeAddr("cashToken"),
                1,
                1
            );
            deployer.addr = address(_deployer);
            _initialZeroAccounts.push(deployer.addr);
            _initialZeroBalances.push(0);
            _actors.push(deployer);
            _receivers.push(deployer);

            zeroToken = new ZeroToken(
                deployer.addr,
                _initialZeroAccounts,
                _initialZeroBalances
            );

            // token actor needs a bespoke setup
            (guy.addr, guy.key) = makeAddrAndKey("ZeroToken");
            guy.addr = address(zeroToken);
            _receivers.push(guy);
            vm.prank(_deployer.lastDeploy());
            zeroToken.mint(guy.addr, 1e12);

            // we need the StandardGovernor
            _standardGovernor.addr = address(_deployer.lastDeploy());
            _actors.push(_standardGovernor);
            _receivers.push(_standardGovernor);
            vm.prank(_standardGovernor.addr);
            zeroToken.mint(_standardGovernor.addr, 1e12);
        }

        _zeroTokenHandler = new ZeroTokenHandler(
            address(this),
            zeroToken,
            deployer,
            _standardGovernor
        );

        _zeroTokenHandler.init(_actors, _receivers);

        bytes4[] memory selectors = new bytes4[](18);
        selectors[0]  = ZeroTokenHandler.approve.selector;
        selectors[1]  = ZeroTokenHandler.transfer.selector;
        selectors[2]  = ZeroTokenHandler.transferFrom.selector;
        selectors[3]  = ZeroTokenHandler.transferWithAuthorization.selector;
        selectors[4]  = ZeroTokenHandler.transferWithAuthorizationWithSignature.selector;
        selectors[5]  = ZeroTokenHandler.transferWithAuthorizationWithVS.selector;
        selectors[6]  = ZeroTokenHandler.receiveWithAuthorization.selector;
        selectors[7]  = ZeroTokenHandler.receiveWithAuthorizationWithSignature.selector;
        selectors[8]  = ZeroTokenHandler.receiveWithAuthorizationWithVS.selector;
        selectors[9]  = ZeroTokenHandler.cancelAuthorization.selector;
        selectors[10] = ZeroTokenHandler.cancelAuthorizationWithSignature.selector;
        selectors[11] = ZeroTokenHandler.cancelAuthorizationWithVS.selector;
        selectors[12] = ZeroTokenHandler.permit.selector;
        selectors[13] = ZeroTokenHandler.permitWithSignature.selector;
        selectors[14] = ZeroTokenHandler.mint.selector;
        selectors[15] = ZeroTokenHandler.delegate.selector;
        selectors[16] = ZeroTokenHandler.delegateBySig.selector;
        selectors[17] = ZeroTokenHandler.delegateBySigWithSignature.selector;

        targetSelector(FuzzSelector({
            addr: address(_zeroTokenHandler),
            selectors: selectors
        }));

        targetContract(address(_zeroTokenHandler));
    }

    //
    // metadata invariants
    //
    function invariant_ZT_M1() public leap {
        require(
            zeroToken.decimals() == 6, "Metadata Invariant ZT_M1"
        );
    }

    //
    // balance invariants
    //
    function invariant_ZT_B1() public leap {
        uint256 balance;
        uint256 actorCount = _zeroTokenHandler.getActorsCount();

        for (uint256 i = 0; i < actorCount; i++) {
            InvariantUtils.Actor memory actor;
            (actor.addr, actor.key) = _zeroTokenHandler.actors(i);
            balance += zeroToken.balanceOf(actor.addr);
        }

        require(
            balance == zeroToken.totalSupply(), "Balance Invariant ZT_B1"
        );
    }

    //
    // permission invariants
    //
    function invariant_ZT_P1() public leap {
        require(
            _zeroTokenHandler.standardGovernorDeployerViolationCount() == 0,
            "Auth Invariant ZT_P1"
        );
    }

    //
    // allowance invariants
    //
    function invariant_ZT_A1() public leap {
        require(
            _zeroTokenHandler.maxAllowanceViolationCount() == 0,
            "Allowance Invariant ZT_A1"
        );
    }

    function invariant_ZT_A2() public leap {
        require(
            _zeroTokenHandler.spendAllowanceViolationCount() == 0,
            "Allowance Invariant ZT_A2"
        );
    }

    function invariant_ZT_A3() public leap {
        require(
            _zeroTokenHandler.invalidNonce2612Count() == 0,
            "Allowance Invariant ZT_A3"
        );
    }

    //
    // EIP-3009 Authorization Invariants
    //
    function invariant_ZT_Z1() public leap {
        require(
            _zeroTokenHandler.nonceViolation3009Count() == 0,
            "Authorization Invariant ZT_Z1"
        );
    }

    function invariant_ZT_Z2() public leap {
        require(
            _zeroTokenHandler.EIP3009ValidViolationCount() == 0,
            "Authorization Invariant ZT_Z2"
        );
    }

    function invariant_ZT_Z3() public leap {
        require(
            _zeroTokenHandler.EIP3009AllowanceViolationCount() == 0,
            "Authorization Invariant ZT_Z3"
        );
    }

    // TODO: add address(0) invariant checks if issue 64 requires changes

    //
    // EIP-5805 Vote Delegation Invariants
    //

    // invariant_ZT_VD1:
    //      For all timepoints t < clock, getVotes(address(0)) and
    //      getPastVotes(address(0), t) SHOULD return 0.
    function invariant_ZT_VD1() public leap {
        // check past epochs
        for (uint256 t = 0; t < zeroToken.clock(); t++) {
            require(
                zeroToken.getPastVotes(address(0), t) == 0,
                "EIP-5805 Vote Delegation Invariant ZT_VD1"
            );
        }

        // check current epoch
        require(
            zeroToken.getVotes(address(0)) == 0,
            "EIP-5805 Vote Delegation Invariant ZT_VD1"
        );
    }

    // invariant_ZT_VD2:
    //      For all accounts a != 0, getVotes(a) SHOULD be the sum of the
    //      “balances” of all the accounts that delegate to a.
    function invariant_ZT_VD2() public leap {
        uint256 balance;
        uint256 actorCount = _zeroTokenHandler.getActorsCount();
        InvariantUtils.Actor memory actor1;
        InvariantUtils.Actor memory actor2;

        for (uint256 i = 0; i < actorCount; i++) {
            (actor1.addr, actor1.key) = _zeroTokenHandler.actors(i);
            if (actor1.addr != address(0)) {
                for (uint256 j = 0; j < actorCount; j++) {
                    (actor2.addr, actor2.key) = _zeroTokenHandler.actors(j);
                    if (actor2.addr != address(0) &&
                        actor1.addr == zeroToken.delegates(actor2.addr)) {
                        balance += zeroToken.balanceOf(actor2.addr);
                    }
                }

                require(
                    balance == zeroToken.getVotes(actor1.addr),
                    "EIP-5805 Vote Delegation Invariant ZT_VD2"
                );

                balance = 0;
            }
        }
    }

    // invariant_ZT_VD3:
    //      For all accounts a != 0 and all timestamp t < clock,
    //      getPastVotes(a, t) SHOULD be the sum of the “balances” of all the
    //      accounts that delegated to a when clock overtook t.
    function invariant_ZT_VD3() public leap {
        uint256 balance;
        uint256 actorCount = _zeroTokenHandler.getActorsCount();
        InvariantUtils.Actor memory actor1;
        InvariantUtils.Actor memory actor2;

        for (uint256 t = 0; t < zeroToken.clock(); t++) {
            for (uint256 i = 0; i < actorCount; i++) {
                (actor1.addr, actor1.key) = _zeroTokenHandler.actors(i);
                if (actor1.addr != address(0)) {
                    for (uint256 j = 0; j < actorCount; j++) {
                        (actor2.addr, actor2.key) = _zeroTokenHandler.actors(j);
                        if (actor2.addr != address(0) &&
                            actor1.addr == zeroToken.pastDelegates(actor2.addr, t)) {
                            balance += zeroToken.pastBalanceOf(actor2.addr, t);
                        }
                    }

                    require(
                        balance == zeroToken.getPastVotes(actor1.addr, t),
                        "EIP-5805 Vote Delegation Invariant ZT_VD3"
                    );

                    balance = 0;
                }
            }
        }
    }

    // invariant_ZT_VD4:
    //      For all accounts a, getPastVotes(a, t) MUST be constant after
    //      t < clock is reached.
    function invariant_ZT_VD4() public leap {
        for (uint256 t = 0; t < zeroToken.clock(); t++) {
            require(
                _zeroTokenHandler.pastVotesAreConst(IToken(address(zeroToken)), t),
                "EIP-5805 Vote Delegation Invariant ZT_VD4"
            );
        }
    }

     // invariant_ZT_VD5:
     //      For all accounts a, pastBalanceOf(a, t) MUST be constant after
     //      t < clock is reached.
     function invariant_ZT_VD5() public leap {
         for (uint256 t = 0; t < zeroToken.clock(); t++) {
             require(
                 _zeroTokenHandler.pastBalancesAreConst(IToken(address(zeroToken)), t),
                 "EIP-5805 Vote Delegation Invariant ZT_VD5"
             );
         }
     }

     // invariant_ZT_VD6:
     //      For all accounts a, pastDelegates(a, t) MUST be constant after
     //      t < clock is reached.
     function invariant_ZT_VD6() public leap {
         for (uint256 t = 0; t < zeroToken.clock(); t++) {
             require(
                 _zeroTokenHandler.pastDelegatesAreConst(IToken(address(zeroToken)), t),
                 "EIP-5805 Vote Delegation Invariant ZT_VD6"
             );
         }
     }

     // Functions don't exceed max gas
    function invariant_ZT_G1() public leap {
        require(
            _zeroTokenHandler.gasViolations() == 0,
            "Gas Invariant ZT_G1"
        );
    }
}

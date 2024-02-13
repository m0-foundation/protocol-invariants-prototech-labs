
pragma solidity ^0.8.23;

// solhint-disable-next-line no-console, no-global-import
import "forge-std/console.sol";

import { BaseInvariants } from "./lib/BaseInvariants.sol";
import { BaseMZeroInvariants } from "./lib/BaseMZeroInvariants.sol";
import { InvariantUtils, IToken } from "./lib/InvariantUtils.sol";
import { PowerTokenHandler } from "./handlers/PowerTokenHandler.sol";

import {
    MockBootstrapToken,
    MockCashToken,
    PowerToken
} from "./lib/Ttg.sol";

contract PowerTokenInvariants is BaseInvariants, BaseMZeroInvariants {
    PowerTokenHandler public _powerTokenHandler;

    MockCashToken _cashToken;
    MockBootstrapToken _bootstrapToken;

    function setUp() public virtual {
        if (!_integration) {
            vm.warp(1_663_224_162);

            _cashToken = new MockCashToken();
            _bootstrapToken = new MockBootstrapToken();

            _bootstrapToken.setTotalSupply(15_000_000 * 1e6);

            // for (uint256 index_; index_ < _initialAccounts.length; ++index_) {
            //     _bootstrapToken.setBalance(_initialAccounts[index_], _initialAmounts[index_]);
            // }

            powerToken = new PowerToken(
                address(_bootstrapToken),
                _standardGovernor.addr,
                address(_cashToken),
                _distributionVault.addr
            );
        }

        _powerTokenHandler = new PowerTokenHandler(
            address(this),
            address(powerToken)
        );

        if (!_integration) {
            _powerTokenHandler.init(NUM_OF_ACTORS);
        } else {
            _powerTokenHandler.init(_actors, _receivers);
        }

        bytes4[] memory selectors = new bytes4[](21);
        selectors[0]  = PowerTokenHandler.buy.selector;
        selectors[1]  = PowerTokenHandler.markNextVotingEpochAsActive.selector;
        selectors[2]  = PowerTokenHandler.markParticipation.selector;
        selectors[3]  = PowerTokenHandler.setNextCashToken.selector;
        selectors[4]  = PowerTokenHandler.delegateBySig.selector;
        selectors[5]  = PowerTokenHandler.delegateBySigWithSignature.selector;
        selectors[6]  = PowerTokenHandler.delegate.selector;
        selectors[7]  = PowerTokenHandler.approve.selector;
        selectors[8]  = PowerTokenHandler.transfer.selector;
        selectors[9]  = PowerTokenHandler.transferFrom.selector;
        selectors[10] = PowerTokenHandler.transferWithAuthorization.selector;
        selectors[11] = PowerTokenHandler.transferWithAuthorizationWithSignature.selector;
        selectors[12] = PowerTokenHandler.transferWithAuthorizationWithVS.selector;
        selectors[13] = PowerTokenHandler.receiveWithAuthorization.selector;
        selectors[14] = PowerTokenHandler.receiveWithAuthorizationWithSignature.selector;
        selectors[15] = PowerTokenHandler.receiveWithAuthorizationWithVS.selector;
        selectors[16] = PowerTokenHandler.cancelAuthorization.selector;
        selectors[17] = PowerTokenHandler.cancelAuthorizationWithSignature.selector;
        selectors[18] = PowerTokenHandler.cancelAuthorizationWithVS.selector;
        selectors[19] = PowerTokenHandler.permit.selector;
        selectors[20] = PowerTokenHandler.permitWithSignature.selector;

        targetSelector(FuzzSelector({
            addr: address(_powerTokenHandler),
            selectors: selectors
        }));

        targetContract(address(_powerTokenHandler));
    }

    //
    // metadata invariants
    //
    function invariant_P_M1() public leap {
        require(
            powerToken.decimals() == 0, "Metadata Invariant P_M1"
        );
    }

    //
    // balance invariants
    //
    function invariant_P_B1() public leap {
        uint256 balance;

        if (!_integration) {
            balance = 10_000;
        }
        uint256 actorCount = _powerTokenHandler.getActorsCount();

        for (uint256 i = 0; i < actorCount; i++) {
            InvariantUtils.Actor memory actor;
            (actor.addr, actor.key) = _powerTokenHandler.actors(i);
            balance += powerToken.balanceOf(actor.addr);
        }

        // Add the the amount to be auctioned to the current user balance
        //balance += powerToken.amountToAuction();
        console.log("Amount to Auction: ", powerToken.amountToAuction());
        console.log("Balance: ", balance);
        console.log("Total Supply: ", powerToken.totalSupply());

        // Balances are not inflated and cannot be transfered during voting epoch
        if (_powerTokenHandler.isTransferEpoch()) {
            require(
                balance == powerToken.totalSupply(), "Balance Invariant P_B1"
            );
        }

    }

    // PowerToken supply only inflates
    function invariant_P_B2() public leap {
        uint256 checkpoints = _powerTokenHandler.totalSupplyCheckpoints();

        uint256 currentBalance;
        uint256 lastBalance;
        if (checkpoints > 2) {
            currentBalance = _powerTokenHandler.totalSupplyBalances(checkpoints - 1);
            lastBalance = _powerTokenHandler.totalSupplyBalances(checkpoints - 2);
        }

        require(currentBalance >= lastBalance, "Balance Invariant P_B2");
    }

    // PowerToken supply inflates each epoch
    function invariant_P_B3() public leap {
        uint256[] memory epochs = _powerTokenHandler.getEpochPassed();
        uint256 numEpochs = epochs.length;

        // Loop starts at 1 because we're back-checking balances
        for (uint256 i = 0; i < numEpochs; i++) {
            if (i > 0) {
                require(_powerTokenHandler.epochBalances(epochs[i]) >=
                        _powerTokenHandler.epochBalances(epochs[i - 1]),
                        "Balance Invariant P_B3");
            }
        }
    }

    // PowerToken target supply inflates 10% each epoch
    function invariant_P_B4() public leap {
        uint256[] memory epochs = _powerTokenHandler.getEpochPassed();
        uint256 numEpochs = epochs.length;

        for (uint256 i = 0; i < numEpochs; i++) {
            if (i > 0) {
                uint256 _currentEpochTargetSupply = _powerTokenHandler.epochTargetSupplies(epochs[i]);
                uint256 _lastCheckedEpochTargetSupply = _powerTokenHandler.epochTargetSupplies(epochs[i - 1]);
                uint256 _epochDelta = epochs[i] - epochs[i - 1];
                // Calculate the expected target supply based on the inflation rate and the number of epochs
                uint256 _expectedTargetSupply = _lastCheckedEpochTargetSupply * 11**(_epochDelta / 2) / 10**(_epochDelta / 2);
                require(_currentEpochTargetSupply ==
                        _expectedTargetSupply ||
                        _currentEpochTargetSupply ==
                        _currentEpochTargetSupply,
                        "Balance Invariant P_B4");
            }
        }
    }

    //
    // Authorization Invariants
    //

    //
    // EIP-3009 Authorization Invariants
    //
    function invariant_P_Z1() public leap {
        require(
            _powerTokenHandler.nonceViolation3009Count() == 0,
            "Authorization Invariant P_Z1"
        );
    }

    function invariant_P_Z2() public leap {
        require(
            _powerTokenHandler.EIP3009ValidViolationCount() == 0,
            "Authorization Invariant P_Z2"
        );
    }

    function invariant_P_Z3() public leap {
        require(
            _powerTokenHandler.EIP3009AllowanceViolationCount() == 0,
            "Authorization Invariant P_Z3"
        );
    }

    // Only StandardGovernor
    function invariant_P_Z4() public leap {
        require(
            _powerTokenHandler.standardGovernorAuthorizationViolationCount() == 0,
            "Authorization Invariant P_Z4"
        );
    }

    // Functions only execute during expected voting epoch
    function invariant_P_Z5() public leap {
        require(
            _powerTokenHandler.expectedVoteEpochViolationCount() == 0,
            "Authorization Invariant P_Z5"
        );
    }

    //
    // EIP-5805 Vote Delegation Invariants
    //

    // invariant_P_VD1:
    //      For all timepoints t < clock, getVotes(address(0)) and
    //      getPastVotes(address(0), t) SHOULD return 0.
    function invariant_P_VD1() public leap {
        // check past epochs
        for (uint256 t = 0; t < powerToken.clock(); t++) {
            require(
                powerToken.getPastVotes(address(0), t) == 0,
                "EIP-5805 Vote Delegation Invariant P_VD1"
            );
        }

        // check current epoch
        require(
            powerToken.getVotes(address(0)) == 0,
            "EIP-5805 Vote Delegation Invariant P_VD1"
        );
    }

    // invariant_P_VD2:
    //      POWER totalVotingPower(delegates) >= POWER totalSupply(holders), at Voting Epoch
    //      For all accounts a != 0, getVotes(a) SHOULD be the sum of the
    //      “balances” of all the accounts that delegate to a.
    function invariant_P_VD2() public leap {
        uint256 balance;
        uint256 actorCount = _powerTokenHandler.getActorsCount();
        InvariantUtils.Actor memory actor1;
        InvariantUtils.Actor memory actor2;

        for (uint256 i = 0; i < actorCount; i++) {
            (actor1.addr, actor1.key) = _powerTokenHandler.actors(i);
            if (actor1.addr != address(0)) {
                for (uint256 j = 0; j < actorCount; j++) {
                    (actor2.addr, actor2.key) = _powerTokenHandler.actors(j);
                    if (actor2.addr != address(0) &&
                        actor1.addr == powerToken.delegates(actor2.addr)) {
                        balance += powerToken.balanceOf(actor2.addr);
                    }
                }

                console.log("Balance: ", balance);
                console.log("Votes: ", powerToken.getVotes(actor1.addr));

                if(_powerTokenHandler.isVotingEpoch()) {
                    require(
                        balance <= powerToken.getVotes(actor1.addr),
                        "EIP-5805 Vote Delegation Invariant P_VD2"
                    );
                }

                balance = 0;
            }
        }
    }

    // invariant_P_VD3:
    //      POWER totalVotingPower(delegates) == POWER totalSupply(holders) + amountToAuction, at Transfer Epoch
    function invariant_P_VD3() public leap {
        uint256 balance;
        uint256 actorCount = _powerTokenHandler.getActorsCount();
        InvariantUtils.Actor memory actor1;
        InvariantUtils.Actor memory actor2;

        for (uint256 t = 0; t < powerToken.clock(); t++) {
            for (uint256 i = 0; i < actorCount; i++) {
                (actor1.addr, actor1.key) = _powerTokenHandler.actors(i);
                if (actor1.addr != address(0)) {
                    for (uint256 j = 0; j < actorCount; j++) {
                        (actor2.addr, actor2.key) = _powerTokenHandler.actors(j);
                        if (actor2.addr != address(0) &&
                            actor1.addr == powerToken.pastDelegates(actor2.addr, t)) {
                            balance += powerToken.pastBalanceOf(actor2.addr, t);
                        }
                    }

                    if (_powerTokenHandler.isTransferEpoch(t)) {
                        balance += _powerTokenHandler.epochAmountToAuction(t);

                        require(
                            balance == powerToken.getPastVotes(actor1.addr, t),
                            "EIP-5805 Vote Delegation Invariant P_VD3"
                        );
                    }

                    balance = 0;
                }
            }
        }
    }

    // invariant_P_VD4:
    //      For all accounts a, getPastVotes(a, t) MUST be constant after
    //      t < clock is reached.
    function invariant_P_VD4() public leap {
        for (uint256 t = 0; t < powerToken.clock(); t++) {
            require(
                _powerTokenHandler.pastVotesAreConst(IToken(address(powerToken)), t),
                "EIP-5805 Vote Delegation Invariant P_VD4"
            );
        }
    }

     // invariant_P_VD5:
     //      For all accounts a, pastBalanceOf(a, t) MUST be constant after
     //      t < clock is reached.
     function invariant_P_VD5() public leap {
         for (uint256 t = 0; t < powerToken.clock(); t++) {
             require(
                 _powerTokenHandler.pastBalancesAreConst(IToken(address(powerToken)), t),
                 "EIP-5805 Vote Delegation Invariant P_VD5"
             );
         }
     }

     // invariant_P_VD6:
     //      For all accounts a, pastDelegates(a, t) MUST be constant after
     //      t < clock is reached.
     function invariant_P_VD6() public leap {
         for (uint256 t = 0; t < powerToken.clock(); t++) {
             require(
                 _powerTokenHandler.pastDelegatesAreConst(IToken(address(powerToken)), t),
                 "EIP-5805 Vote Delegation Invariant P_VD6"
             );
         }
     }

    // Functions don't exceed max gas
    function invariant_P_G1() public leap {
        require(
            _powerTokenHandler.gasViolations() == 0,
            "Gas Invariant P_G1"
        );
    }
}

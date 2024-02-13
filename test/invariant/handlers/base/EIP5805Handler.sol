pragma solidity ^0.8.23;

import "./BaseHandler.sol";

abstract contract EIP5805Handler is BaseHandler {
    // EIP5805 state
    mapping(uint256 => mapping(address => bool)) public pastVotesCached;
    mapping(uint256 => mapping(address => uint256)) public pastVotesCache;
    mapping(uint256 => mapping(address => bool)) public pastBalancesCached;
    mapping(uint256 => mapping(address => uint256)) public pastBalancesCache;
    mapping(uint256 => mapping(address => bool)) public pastDelegatesCached;
    mapping(uint256 => mapping(address => address)) public pastDelegatesCache;

    constructor() {}

    function pastVotesAreConst(
        IToken _token,
        uint256 _epoch
    ) external returns (bool) {
        for(uint256 i = 0; i < actors.length; i++) {
            if (pastVotesCached[_epoch][actors[i].addr]) {
                if (pastVotesCache[_epoch][actors[i].addr] !=
                    _token.getPastVotes(actors[i].addr, _epoch)) {
                    return false;
                }
            } else {
                pastVotesCached[_epoch][actors[i].addr] = true;
                pastVotesCache[_epoch][actors[i].addr] =
                    _token.getPastVotes(actors[i].addr, _epoch);
            }
        }

        return true;
    }

    function pastBalancesAreConst(
        IToken _token,
        uint256 _epoch
    ) external returns (bool) {
        for(uint256 i = 0; i < actors.length; i++) {
            if (pastBalancesCached[_epoch][actors[i].addr]) {
                if (pastBalancesCache[_epoch][actors[i].addr] !=
                    _token.pastBalanceOf(actors[i].addr, _epoch)) {
                    return false;
                }
            } else {
                pastBalancesCached[_epoch][actors[i].addr] = true;
                pastBalancesCache[_epoch][actors[i].addr] =
                    _token.pastBalanceOf(actors[i].addr, _epoch);
            }
        }

        return true;
    }

    function pastDelegatesAreConst(
        IToken _token,
        uint256 _epoch
    ) external returns (bool) {
        for(uint256 i = 0; i < actors.length; i++) {
            if (pastDelegatesCached[_epoch][actors[i].addr]) {
                if (pastDelegatesCache[_epoch][actors[i].addr] !=
                    _token.pastDelegates(actors[i].addr, _epoch)) {
                    return false;
                }
            } else {
                pastDelegatesCached[_epoch][actors[i].addr] = true;
                pastDelegatesCache[_epoch][actors[i].addr] =
                    _token.pastDelegates(actors[i].addr, _epoch);
            }
        }

        return true;
    }
}

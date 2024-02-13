pragma solidity ^0.8.23;

import "./BaseHandler.sol";

abstract contract EIP3009Handler is BaseHandler {
    // to determine what nonce states have been burned for 3009
    mapping(address => mapping(bytes32 => bool)) public nonceState;

    // to determine if allowance has changed for 3009
    mapping(address account => mapping(address spender => uint256 allowance)) public allowanceBefore;

    // EIP3009 violation counters
    uint256 public EIP3009AllowanceViolationCount;
    uint256 public EIP3009ValidViolationCount;
    uint256 public nonceViolation3009Count;

    constructor() {}

    function snapAllowanceValues(IToken _token) public {
        for(uint256 i = 0; i < actors.length; i++) {
            for(uint256 j = 0; j < actors.length; j++) {
                allowanceBefore[actors[i].addr][actors[j].addr] =
                    _token.allowance(actors[i].addr, actors[j].addr);
            }
        }
    }

    function allowanceDiff(IToken _token) public view returns (bool) {
        for(uint256 i = 0; i < actors.length; i++) {
            for(uint256 j = 0; j < actors.length; j++) {
                if(allowanceBefore[actors[i].addr][actors[j].addr] !=
                    _token.allowance(actors[i].addr, actors[j].addr)) {
                    return true;
                }
            }
        }

        return false;
    }
}

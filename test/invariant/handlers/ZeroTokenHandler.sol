// SPDX-FileCopyrightText: © 2024 Prototech Labs <info@prototechlabs.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright © 2024 Christopher Mooney
// Copyright © 2024 Chris Smith
// Copyright © 2024 Brian McMichael
// Copyright © 2024 Derek Flossman
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

pragma solidity ^0.8.23;

import { Test } from "forge-std/Test.sol";
import "./base/BaseHandler.sol";
import { EIP3009Handler } from "./base/EIP3009Handler.sol";
import { EIP5805Handler } from "./base/EIP5805Handler.sol";
import { ZeroToken } from "../lib/Ttg.sol";

contract ZeroTokenHandler is BaseHandler, EIP3009Handler, EIP5805Handler {
    ZeroToken public zeroToken;
    InvariantUtils.Actor public standardGovernorDeployerActor;
    InvariantUtils.Actor public standardGovernorActor;

    // violation counters
    uint256 public invalidNonce2612Count;
    uint256 public maxAllowanceViolationCount;
    uint256 public standardGovernorDeployerViolationCount;
    uint256 public spendAllowanceViolationCount;

    // state
    bool public firstMaxAllowance = true;

    constructor(
        address _testContract,
        ZeroToken _zeroToken,
        InvariantUtils.Actor memory _standardGovernorDeployerActor,
        InvariantUtils.Actor memory _standardGovernor
    ) BaseHandler(_testContract) {
        zeroToken = _zeroToken;
        standardGovernorDeployerActor = _standardGovernorDeployerActor;
        standardGovernorActor = _standardGovernor;
    }

    function init(
        InvariantUtils.Actor[] memory _actors,
        InvariantUtils.Actor[] memory _receivers
    ) external {
        for(uint256 i = 0; i < _actors.length; i++) {
            msgSenders.push(_actors[i]);
        }

        validateActors(msgSenders);

        for(uint256 i = 0; i < _receivers.length; i++) {
            actors.push(_receivers[i]);
        }

        validateActors(actors);
    }

    //
    // Testable functions
    //
    function approve(
        uint256 _actorIndex,
        uint256 _spenderIndex,
        uint256 _amount
    ) external resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        InvariantUtils.Actor memory spender = actors[bound(_spenderIndex, 0, actors.length - 1)];

        startGas();
        try zeroToken.approve(spender.addr, (firstMaxAllowance) ? type(uint256).max : _amount) {
            stopGas();

            firstMaxAllowance = false;
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            expectedError(_err);
        }
    }

    function transfer(
        uint256 _actorIndex,
        uint256 _recipientIndex,
        uint256 _amount
    ) external resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        InvariantUtils.Actor memory recipient = actors[bound(_recipientIndex, 0, actors.length - 1)];
        _amount = bound(_amount, 0, zeroToken.balanceOf(actor.addr));

        startGas();
        try zeroToken.transfer(recipient.addr, _amount) {
            stopGas();
            // success
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            expectedError(_err);
        }
    }

    function transferFrom(
        uint256 _actorIndex,
        uint256 _fromIndex,
        uint256 _toIndex,
        uint256 _amount
    ) external resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        bool maxAllowance = false;
        InvariantUtils.Actor memory to = actors[bound(_toIndex, 0, actors.length - 1)];
        InvariantUtils.Actor memory from = actors[bound(_fromIndex, 0, actors.length - 1)];
        uint256 beforeAllowance = zeroToken.allowance(from.addr, actor.addr);

        if (beforeAllowance == type(uint256).max) {
            maxAllowance = true;
        }

        _amount = bound(
            _amount,
            0,
            uint240((zeroToken.balanceOf(from.addr) >=  zeroToken.allowance(from.addr, actor.addr)) ?
                zeroToken.balanceOf(from.addr) :
                zeroToken.allowance(from.addr, actor.addr))
        );

        startGas();
        try zeroToken.transferFrom(from.addr, to.addr, _amount) {
            stopGas();

            if (maxAllowance &&
                zeroToken.allowance(from.addr, actor.addr) != type(uint256).max) {
                maxAllowanceViolationCount++;
            }
            if (!maxAllowance &&
                beforeAllowance != zeroToken.allowance(from.addr, actor.addr) + _amount) {
                spendAllowanceViolationCount++;
            }
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (_amount > zeroToken.allowance(from.addr, actor.addr) ||
                _amount > zeroToken.balanceOf(from.addr)) {
                addExpectedError("InsufficientAllowance(address,uint256,uint256)");
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
            }
            expectedError(_err);
        }
    }

    function transferWithAuthorization(
        uint256 _actorIndex,
        uint256 _fromIndex,
        uint256 _toIndex,
        uint256 _amount,
        uint256 _validAfter,
        uint256 _validBefore,
        uint256 _nonce
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory to = actors[bound(_toIndex, 0, actors.length - 1)];
        InvariantUtils.Actor memory from = actors[bound(_fromIndex, 0, actors.length - 1)];
        _validAfter = bound(_validAfter, 0, block.timestamp * 2);
        _validBefore = bound(_validBefore, _validAfter, block.timestamp * 2);
        _nonce = bound(_nonce, 0, MAX_NONCE);

        // get a snapshot of allowance values
        snapAllowanceValues(IToken(address(zeroToken)));

        _amount = bound(
            _amount,
            0,
            uint240((zeroToken.balanceOf(from.addr) >=  zeroToken.allowance(actor.addr, from.addr)) ?
                zeroToken.balanceOf(from.addr) :
                zeroToken.allowance(actor.addr, from.addr))
        );

        { // fix stack too deep
            bytes32 digest = InvariantUtils.Get3009Digest(
                IToken(address(zeroToken)),
                from.addr,
                to.addr,
                _amount,
                _validAfter,
                _validBefore,
                bytes32(_nonce),
                zeroToken.TRANSFER_WITH_AUTHORIZATION_TYPEHASH()
            );
            (sign.v, sign.r, sign.s) = vm.sign(from.key, digest);
        }

        // 10% of the time release a signature chaos monkey
        if (bound(_actorIndex, 0, 9) == 0)  {
            sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
            sign.s = bytes32(_actorIndex);
        }

        startGas();
        try zeroToken.transferWithAuthorization(
            from.addr,
            to.addr,
            _amount,
            _validAfter,
            _validBefore,
            bytes32(_nonce),
            sign.v,
            sign.r,
            sign.s
        ) {
            stopGas();

            // ensure no allowances change
            if (allowanceDiff(IToken(address(zeroToken)))) {
                EIP3009AllowanceViolationCount++;
            }
            if (!nonceState[from.addr][bytes32(_nonce)]) {
                nonceState[from.addr][bytes32(_nonce)] = true;
            } else {
                nonceViolation3009Count++;
            }
            if (block.timestamp <= _validAfter ||
                block.timestamp >= _validBefore) {
                EIP3009ValidViolationCount++;
            }
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (nonceState[from.addr][bytes32(_nonce)]) {
                addExpectedError("AuthorizationAlreadyUsed(address,bytes32)");
            }
            if (block.timestamp >= _validBefore) addExpectedError("AuthorizationExpired(uint256,uint256)");
            if (block.timestamp <= _validAfter) addExpectedError("AuthorizationNotYetValid(uint256,uint256)");
            if (from.addr != InvariantUtils.GetAddress(from.key) ||
                bound(_actorIndex, 0, 9) == 0) {
                addExpectedError("InvalidSignatureV()");
                addExpectedError("InvalidSignature()");
                addExpectedError("SignerMismatch()");
            }
            if (_amount > zeroToken.balanceOf(from.addr)) {
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
            }
            expectedError(_err);
        }
    }

    function transferWithAuthorizationWithSignature(
        uint256 _actorIndex,
        uint256 _fromIndex,
        uint256 _toIndex,
        uint256 _amount,
        uint256 _validAfter,
        uint256 _validBefore,
        uint256 _nonce
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory to = actors[bound(_toIndex, 0, actors.length - 1)];
        InvariantUtils.Actor memory from = actors[bound(_fromIndex, 0, actors.length - 1)];
        _validAfter = bound(_validAfter, 0, block.timestamp * 2);
        _validBefore = bound(_validBefore, _validAfter, block.timestamp * 2);
        _nonce = bound(_nonce, 0, MAX_NONCE);

        // get a snapshot of allowance values
        snapAllowanceValues(IToken(address(zeroToken)));

        _amount = bound(
            _amount,
            0,
            uint240((zeroToken.balanceOf(from.addr) >=  zeroToken.allowance(actor.addr, from.addr)) ?
                zeroToken.balanceOf(from.addr) :
                zeroToken.allowance(actor.addr, from.addr))
        );

        { // fix stack too deep
            bytes32 digest = InvariantUtils.Get3009Digest(
                IToken(address(zeroToken)),
                from.addr,
                to.addr,
                _amount,
                _validAfter,
                _validBefore,
                bytes32(_nonce),
                zeroToken.TRANSFER_WITH_AUTHORIZATION_TYPEHASH()
            );
            (sign.v, sign.r, sign.s) = vm.sign(from.key, digest);
        }

        // 10% of the time release a signature chaos monkey
        if (bound(_actorIndex, 0, 9) == 0)  {
            sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
            sign.s = bytes32(_actorIndex);
        }

        bytes memory signature = abi.encodePacked(
            sign.r,
            sign.s,
            sign.v
        );

        startGas();
        try zeroToken.transferWithAuthorization(
            from.addr,
            to.addr,
            _amount,
            _validAfter,
            _validBefore,
            bytes32(_nonce),
            signature
        ) {
            stopGas();

            // ensure no allowances change
            if (allowanceDiff(IToken(address(zeroToken)))) {
                EIP3009AllowanceViolationCount++;
            }
            if (!nonceState[from.addr][bytes32(_nonce)]) {
                nonceState[from.addr][bytes32(_nonce)] = true;
            } else {
                nonceViolation3009Count++;
            }
            if (block.timestamp <= _validAfter ||
                block.timestamp >= _validBefore) {
                EIP3009ValidViolationCount++;
            }
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (nonceState[from.addr][bytes32(_nonce)]) {
                addExpectedError("AuthorizationAlreadyUsed(address,bytes32)");
            }
            if (block.timestamp >= _validBefore) addExpectedError("AuthorizationExpired(uint256,uint256)");
            if (block.timestamp <= _validAfter) addExpectedError("AuthorizationNotYetValid(uint256,uint256)");
            if (from.addr != InvariantUtils.GetAddress(from.key) ||
                bound(_actorIndex, 0, 9) == 0) {
                addExpectedError("InvalidSignatureV()");
                addExpectedError("InvalidSignature()");
                addExpectedError("SignerMismatch()");
            }
            if (_amount > zeroToken.balanceOf(from.addr)) {
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
            }
            expectedError(_err);
        }
    }

    function transferWithAuthorizationWithVS(
        uint256 _actorIndex,
        uint256 _fromIndex,
        uint256 _toIndex,
        uint256 _amount,
        uint256 _validAfter,
        uint256 _validBefore,
        uint256 _nonce
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory to = actors[bound(_toIndex, 0, actors.length - 1)];
        InvariantUtils.Actor memory from = actors[bound(_fromIndex, 0, actors.length - 1)];
        _validAfter = bound(_validAfter, 0, block.timestamp * 2);
        _validBefore = bound(_validBefore, _validAfter, block.timestamp * 2);
        _nonce = bound(_nonce, 0, MAX_NONCE);

        // get a snapshot of allowance values
        snapAllowanceValues(IToken(address(zeroToken)));

        _amount = bound(
            _amount,
            0,
            uint240((zeroToken.balanceOf(from.addr) >=  zeroToken.allowance(actor.addr, from.addr)) ?
                zeroToken.balanceOf(from.addr) :
                zeroToken.allowance(actor.addr, from.addr))
        );

        { // fix stack too deep
            bytes32 digest = InvariantUtils.Get3009Digest(
                IToken(address(zeroToken)),
                from.addr,
                to.addr,
                _amount,
                _validAfter,
                _validBefore,
                bytes32(_nonce),
                zeroToken.TRANSFER_WITH_AUTHORIZATION_TYPEHASH()
            );
            (sign.v, sign.r, sign.s) = vm.sign(from.key, digest);
        }

        // 10% of the time release a signature chaos monkey
        if (bound(_actorIndex, 0, 9) == 0)  {
            sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
            sign.s = bytes32(_actorIndex);
        }

        bytes32 vs = sign.s;

        if (sign.v == 28) {
            // then left-most bit of s has to be flipped to 1 to get vs
            vs = sign.s | bytes32(uint256(1) << 255);
        }

        startGas();
        try zeroToken.transferWithAuthorization(
            from.addr,
            to.addr,
            _amount,
            _validAfter,
            _validBefore,
            bytes32(_nonce),
            sign.r,
            vs
        ) {
            stopGas();

            // ensure no allowances change
            if (allowanceDiff(IToken(address(zeroToken)))) {
                EIP3009AllowanceViolationCount++;
            }
            if (!nonceState[from.addr][bytes32(_nonce)]) {
                nonceState[from.addr][bytes32(_nonce)] = true;
            } else {
                nonceViolation3009Count++;
            }
            if (block.timestamp <= _validAfter ||
                block.timestamp >= _validBefore) {
                EIP3009ValidViolationCount++;
            }
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (nonceState[from.addr][bytes32(_nonce)]) {
                addExpectedError("AuthorizationAlreadyUsed(address,bytes32)");
            }
            if (block.timestamp >= _validBefore) addExpectedError("AuthorizationExpired(uint256,uint256)");
            if (block.timestamp <= _validAfter) addExpectedError("AuthorizationNotYetValid(uint256,uint256)");
            if (from.addr != InvariantUtils.GetAddress(from.key) ||
                bound(_actorIndex, 0, 9) == 0) {
                addExpectedError("InvalidSignatureV()");
                addExpectedError("InvalidSignature()");
                addExpectedError("SignerMismatch()");
            }
            if (_amount > zeroToken.balanceOf(from.addr)) {
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
            }
            expectedError(_err);
        }
    }

    function receiveWithAuthorization(
        uint256 _actorIndex,
        uint256 _fromIndex,
        uint256 _toIndex,
        uint256 _amount,
        uint256 _validAfter,
        uint256 _validBefore,
        uint256 _nonce
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory to = actors[bound(_toIndex, 0, actors.length - 1)];
        InvariantUtils.Actor memory from = actors[bound(_fromIndex, 0, actors.length - 1)];
        _validAfter = bound(_validAfter, 0, block.timestamp * 2);
        _validBefore = bound(_validBefore, _validAfter, block.timestamp * 2);
        _nonce = bound(_nonce, 0, MAX_NONCE);

        // get a snapshot of allowance values
        snapAllowanceValues(IToken(address(zeroToken)));

        _amount = bound(
            _amount,
            0,
            uint240((zeroToken.balanceOf(from.addr) >=  zeroToken.allowance(actor.addr, from.addr)) ?
                zeroToken.balanceOf(from.addr) :
                zeroToken.allowance(actor.addr, from.addr))
        );

        { // fix stack too deep
            bytes32 digest = InvariantUtils.Get3009Digest(
                IToken(address(zeroToken)),
                from.addr,
                to.addr,
                _amount,
                _validAfter,
                _validBefore,
                bytes32(_nonce),
                zeroToken.RECEIVE_WITH_AUTHORIZATION_TYPEHASH()
            );
            (sign.v, sign.r, sign.s) = vm.sign(from.key, digest);
        }

        // 10% of the time release a signature chaos monkey
        if (bound(_actorIndex, 0, 9) == 0)  {
            sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
            sign.s = bytes32(_actorIndex);
        }

        startGas();
        try zeroToken.receiveWithAuthorization(
            from.addr,
            to.addr,
            _amount,
            _validAfter,
            _validBefore,
            bytes32(_nonce),
            sign.v,
            sign.r,
            sign.s
        ) {
            stopGas();

            // ensure no allowances change
            if (allowanceDiff(IToken(address(zeroToken)))) {
                EIP3009AllowanceViolationCount++;
            }
            if (!nonceState[from.addr][bytes32(_nonce)]) {
                nonceState[from.addr][bytes32(_nonce)] = true;
            } else {
                nonceViolation3009Count++;
            }
            if (block.timestamp <= _validAfter ||
                block.timestamp >= _validBefore) {
                EIP3009ValidViolationCount++;
            }
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (nonceState[from.addr][bytes32(_nonce)]) {
                addExpectedError("AuthorizationAlreadyUsed(address,bytes32)");
            }
            if (block.timestamp >= _validBefore) addExpectedError("AuthorizationExpired(uint256,uint256)");
            if (block.timestamp <= _validAfter) addExpectedError("AuthorizationNotYetValid(uint256,uint256)");
            if (actor.addr != to.addr) addExpectedError("CallerMustBePayee(address,address)");
            if (from.addr != InvariantUtils.GetAddress(from.key) ||
                bound(_actorIndex, 0, 9) == 0) {
                addExpectedError("InvalidSignatureV()");
                addExpectedError("InvalidSignature()");
                addExpectedError("SignerMismatch()");
            }
            if (_amount > zeroToken.balanceOf(from.addr)) {
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
            }
            expectedError(_err);
        }
    }

    function receiveWithAuthorizationWithSignature(
        uint256 _actorIndex,
        uint256 _fromIndex,
        uint256 _toIndex,
        uint256 _amount,
        uint256 _validAfter,
        uint256 _validBefore,
        uint256 _nonce
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory to = actors[bound(_toIndex, 0, actors.length - 1)];
        InvariantUtils.Actor memory from = actors[bound(_fromIndex, 0, actors.length - 1)];
        _validAfter = bound(_validAfter, 0, block.timestamp * 2);
        _validBefore = bound(_validBefore, _validAfter, block.timestamp * 2);
        _nonce = bound(_nonce, 0, MAX_NONCE);

        // get a snapshot of allowance values
        snapAllowanceValues(IToken(address(zeroToken)));

        _amount = bound(
            _amount,
            0,
            uint240((zeroToken.balanceOf(from.addr) >=  zeroToken.allowance(actor.addr, from.addr)) ?
                zeroToken.balanceOf(from.addr) :
                zeroToken.allowance(actor.addr, from.addr))
        );

        { // fix stack too deep
            bytes32 digest = InvariantUtils.Get3009Digest(
                IToken(address(zeroToken)),
                from.addr,
                to.addr,
                _amount,
                _validAfter,
                _validBefore,
                bytes32(_nonce),
                zeroToken.RECEIVE_WITH_AUTHORIZATION_TYPEHASH()
            );
            (sign.v, sign.r, sign.s) = vm.sign(from.key, digest);
        }

        // 10% of the time release a signature chaos monkey
        if (bound(_actorIndex, 0, 9) == 0)  {
            sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
            sign.s = bytes32(_actorIndex);
        }

        bytes memory signature = abi.encodePacked(
            sign.r,
            sign.s,
            sign.v
        );

        startGas();
        try zeroToken.receiveWithAuthorization(
            from.addr,
            to.addr,
            _amount,
            _validAfter,
            _validBefore,
            bytes32(_nonce),
            signature
        ) {
            stopGas();

            // ensure no allowances change
            if (allowanceDiff(IToken(address(zeroToken)))) {
                EIP3009AllowanceViolationCount++;
            }
            if (!nonceState[from.addr][bytes32(_nonce)]) {
                nonceState[from.addr][bytes32(_nonce)] = true;
            } else {
                nonceViolation3009Count++;
            }
            if (block.timestamp <= _validAfter ||
                block.timestamp >= _validBefore) {
                EIP3009ValidViolationCount++;
            }
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (nonceState[from.addr][bytes32(_nonce)]) {
                addExpectedError("AuthorizationAlreadyUsed(address,bytes32)");
            }
            if (block.timestamp >= _validBefore) addExpectedError("AuthorizationExpired(uint256,uint256)");
            if (block.timestamp <= _validAfter) addExpectedError("AuthorizationNotYetValid(uint256,uint256)");
            if (actor.addr != to.addr) addExpectedError("CallerMustBePayee(address,address)");
            if (from.addr != InvariantUtils.GetAddress(from.key) ||
                bound(_actorIndex, 0, 9) == 0) {
                addExpectedError("InvalidSignatureV()");
                addExpectedError("InvalidSignature()");
                addExpectedError("SignerMismatch()");
            }
            if (_amount > zeroToken.balanceOf(from.addr)) {
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
            }
            expectedError(_err);
        }
    }

    function receiveWithAuthorizationWithVS(
        uint256 _actorIndex,
        uint256 _fromIndex,
        uint256 _toIndex,
        uint256 _amount,
        uint256 _validAfter,
        uint256 _validBefore,
        uint256 _nonce
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory to = actors[bound(_toIndex, 0, actors.length - 1)];
        InvariantUtils.Actor memory from = actors[bound(_fromIndex, 0, actors.length - 1)];
        _validAfter = bound(_validAfter, 0, block.timestamp * 2);
        _validBefore = bound(_validBefore, _validAfter, block.timestamp * 2);
        _nonce = bound(_nonce, 0, MAX_NONCE);

        // get a snapshot of allowance values
        snapAllowanceValues(IToken(address(zeroToken)));

        _amount = bound(
            _amount,
            0,
            uint240((zeroToken.balanceOf(from.addr) >=  zeroToken.allowance(actor.addr, from.addr)) ?
                zeroToken.balanceOf(from.addr) :
                zeroToken.allowance(actor.addr, from.addr))
        );

        { // fix stack too deep
            bytes32 digest = InvariantUtils.Get3009Digest(
                IToken(address(zeroToken)),
                from.addr,
                to.addr,
                _amount,
                _validAfter,
                _validBefore,
                bytes32(_nonce),
                zeroToken.RECEIVE_WITH_AUTHORIZATION_TYPEHASH()
            );
            (sign.v, sign.r, sign.s) = vm.sign(from.key, digest);
        }

        // 10% of the time release a signature chaos monkey
        if (bound(_actorIndex, 0, 9) == 0)  {
            sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
            sign.s = bytes32(_actorIndex);
        }

        bytes32 vs = sign.s;

        if (sign.v == 28) {
            // then left-most bit of s has to be flipped to 1 to get vs
            vs = sign.s | bytes32(uint256(1) << 255);
        }

        startGas();
        try zeroToken.receiveWithAuthorization(
            from.addr,
            to.addr,
            _amount,
            _validAfter,
            _validBefore,
            bytes32(_nonce),
            sign.r,
            vs
        ) {
            stopGas();

            // ensure no allowances change
            if (allowanceDiff(IToken(address(zeroToken)))) {
                EIP3009AllowanceViolationCount++;
            }
            if (!nonceState[from.addr][bytes32(_nonce)]) {
                nonceState[from.addr][bytes32(_nonce)] = true;
            } else {
                nonceViolation3009Count++;
            }
            if (block.timestamp <= _validAfter ||
                block.timestamp >= _validBefore) {
                EIP3009ValidViolationCount++;
            }
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (nonceState[from.addr][bytes32(_nonce)]) {
                addExpectedError("AuthorizationAlreadyUsed(address,bytes32)");
            }
            if (block.timestamp >= _validBefore) addExpectedError("AuthorizationExpired(uint256,uint256)");
            if (block.timestamp <= _validAfter) addExpectedError("AuthorizationNotYetValid(uint256,uint256)");
            if (actor.addr != to.addr) addExpectedError("CallerMustBePayee(address,address)");
            if (from.addr != InvariantUtils.GetAddress(from.key) ||
                bound(_actorIndex, 0, 9) == 0) {
                addExpectedError("InvalidSignatureV()");
                addExpectedError("InvalidSignature()");
                addExpectedError("SignerMismatch()");
            }
            if (_amount > zeroToken.balanceOf(from.addr)) {
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
            }
            expectedError(_err);
        }
    }

    function cancelAuthorization(
        uint256 _actorIndex,
        uint256 _authorizerIndex,
        uint256 _nonce
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory authorizer = actors[bound(_authorizerIndex, 0, actors.length - 1)];
        _nonce = bound(_nonce, 0, MAX_NONCE);

        { // fix stack too deep
            bytes32 digest = InvariantUtils.Get3009CancelDigest(
                IToken(address(zeroToken)),
                authorizer.addr,
                bytes32(_nonce)
            );
            (sign.v, sign.r, sign.s) = vm.sign(authorizer.key, digest);
        }

        // 10% of the time release a signature chaos monkey
        if (bound(_actorIndex, 0, 9) == 0)  {
            sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
            sign.s = bytes32(_actorIndex);
        }

        startGas();
        try zeroToken.cancelAuthorization(
            authorizer.addr,
            bytes32(_nonce),
            sign.v,
            sign.r,
            sign.s
        ) {
            stopGas();

            if (!nonceState[authorizer.addr][bytes32(_nonce)]) {
                nonceState[authorizer.addr][bytes32(_nonce)] = true;
            } else {
                nonceViolation3009Count++;
            }
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (nonceState[authorizer.addr][bytes32(_nonce)]) {
                addExpectedError("AuthorizationAlreadyUsed(address,bytes32)");
            }
            if (authorizer.addr != InvariantUtils.GetAddress(authorizer.key) ||
                bound(_actorIndex, 0, 9) == 0) {
                addExpectedError("InvalidSignatureV()");
                addExpectedError("InvalidSignature()");
                addExpectedError("SignerMismatch()");
            }
            expectedError(_err);
        }
    }

    function cancelAuthorizationWithSignature(
        uint256 _actorIndex,
        uint256 _authorizerIndex,
        uint256 _nonce
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory authorizer = actors[bound(_authorizerIndex, 0, actors.length - 1)];
        _nonce = bound(_nonce, 0, MAX_NONCE);

        { // fix stack too deep
            bytes32 digest = InvariantUtils.Get3009CancelDigest(
                IToken(address(zeroToken)),
                authorizer.addr,
                bytes32(_nonce)
            );
            (sign.v, sign.r, sign.s) = vm.sign(authorizer.key, digest);
        }

        // 10% of the time release a signature chaos monkey
        if (bound(_actorIndex, 0, 9) == 0)  {
            sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
            sign.s = bytes32(_actorIndex);
        }

        bytes memory signature = abi.encodePacked(
            sign.r,
            sign.s,
            sign.v
        );

        startGas();
        try zeroToken.cancelAuthorization(
            authorizer.addr,
            bytes32(_nonce),
            signature
        ) {
            stopGas();

            if (!nonceState[authorizer.addr][bytes32(_nonce)]) {
                nonceState[authorizer.addr][bytes32(_nonce)] = true;
            } else {
                nonceViolation3009Count++;
            }
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (nonceState[authorizer.addr][bytes32(_nonce)]) {
                addExpectedError("AuthorizationAlreadyUsed(address,bytes32)");
            }
            if (authorizer.addr != InvariantUtils.GetAddress(authorizer.key) ||
                bound(_actorIndex, 0, 9) == 0) {
                addExpectedError("InvalidSignatureV()");
                addExpectedError("InvalidSignature()");
                addExpectedError("SignerMismatch()");
            }
            expectedError(_err);
        }
    }

    function cancelAuthorizationWithVS(
        uint256 _actorIndex,
        uint256 _authorizerIndex,
        uint256 _nonce
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory authorizer = actors[bound(_authorizerIndex, 0, actors.length - 1)];
        _nonce = bound(_nonce, 0, MAX_NONCE);

        { // fix stack too deep
            bytes32 digest = InvariantUtils.Get3009CancelDigest(
                IToken(address(zeroToken)),
                authorizer.addr,
                bytes32(_nonce)
            );
            (sign.v, sign.r, sign.s) = vm.sign(authorizer.key, digest);
        }

        // 10% of the time release a signature chaos monkey
        if (bound(_actorIndex, 0, 9) == 0)  {
            sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
            sign.s = bytes32(_actorIndex);
        }

        bytes32 vs = sign.s;

        if (sign.v == 28) {
            // then left-most bit of s has to be flipped to 1 to get vs
            vs = sign.s | bytes32(uint256(1) << 255);
        }

        startGas();
        try zeroToken.cancelAuthorization(
            authorizer.addr,
            bytes32(_nonce),
            sign.r,
            vs
        ) {
            stopGas();

            if (!nonceState[authorizer.addr][bytes32(_nonce)]) {
                nonceState[authorizer.addr][bytes32(_nonce)] = true;
            } else {
                nonceViolation3009Count++;
            }
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (nonceState[authorizer.addr][bytes32(_nonce)]) {
                addExpectedError("AuthorizationAlreadyUsed(address,bytes32)");
            }
            if (authorizer.addr != InvariantUtils.GetAddress(authorizer.key) ||
                bound(_actorIndex, 0, 9) == 0) {
                addExpectedError("InvalidSignatureV()");
                addExpectedError("InvalidSignature()");
                addExpectedError("SignerMismatch()");
            }
            expectedError(_err);
        }
    }

    function permit(
        uint256 _actorIndex,
        uint256 _fromIndex,
        uint256 _spenderIndex,
        uint256 _amount,
        uint256 _nonce,
        uint256 _deadline
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory from = actors[bound(_fromIndex, 0, actors.length - 1)];
        InvariantUtils.Actor memory spender = actors[bound(_spenderIndex, 0, actors.length - 1)];
        _nonce = bound(
            _nonce,
            (zeroToken.nonces(from.addr) > 0) ? zeroToken.nonces(from.addr) - 1 : 0,
            zeroToken.nonces(from.addr) + 1
        );

        { // fix stack too deep
            bytes32 digest = InvariantUtils.GetPermitDigest(
                IToken(address(zeroToken)),
                from.addr,
                spender.addr,
                _amount,
                _nonce,
                _deadline
            );
            (sign.v, sign.r, sign.s) = vm.sign(from.key, digest);
        }

        // 10% of the time release a signature chaos monkey
        if (bound(_actorIndex, 0, 9) == 0)  {
            sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
            sign.s = bytes32(_actorIndex);
        }

        startGas();
        try zeroToken.permit(
            from.addr,
            spender.addr,
            _amount,
            _deadline,
            sign.v,
            sign.r,
            sign.s
        ) {
            stopGas();

            if ((zeroToken.nonces(from.addr) - 1) != _nonce) {
                invalidNonce2612Count++;
            }
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (from.addr != InvariantUtils.GetAddress(from.key) ||
                _nonce != zeroToken.nonces(from.addr) ||
                bound(_actorIndex, 0, 9) == 0) {
                addExpectedError("InvalidSignatureV()");
                addExpectedError("InvalidSignature()");
                addExpectedError("SignerMismatch()");
            }
            if (block.timestamp > _deadline) addExpectedError("SignatureExpired(uint256,uint256)");
            expectedError(_err);
        }
    }

    function permitWithSignature(
        uint256 _actorIndex,
        uint256 _fromIndex,
        uint256 _spenderIndex,
        uint256 _amount,
        uint256 _nonce,
        uint256 _deadline
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory from = actors[bound(_fromIndex, 0, actors.length - 1)];
        InvariantUtils.Actor memory spender = actors[bound(_spenderIndex, 0, actors.length - 1)];
        _nonce = bound(
            _nonce,
            (zeroToken.nonces(from.addr) > 0) ? zeroToken.nonces(from.addr) - 1 : 0,
            zeroToken.nonces(from.addr) + 1
        );

        { // fix stack too deep
            bytes32 digest = InvariantUtils.GetPermitDigest(
                IToken(address(zeroToken)),
                from.addr,
                spender.addr,
                _amount,
                _nonce,
                _deadline
            );
            (sign.v, sign.r, sign.s) = vm.sign(from.key, digest);
        }

        // 10% of the time release a signature chaos monkey
        if (bound(_actorIndex, 0, 9) == 0)  {
            sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
            sign.s = bytes32(_actorIndex);
        }

        bytes memory signature = abi.encodePacked(
            sign.r,
            sign.s,
            sign.v
        );

        startGas();
        try zeroToken.permit(
            from.addr,
            spender.addr,
            _amount,
            _deadline,
            signature
        ) {
            stopGas();

            if ((zeroToken.nonces(from.addr) - 1) != _nonce) {
                invalidNonce2612Count++;
            }
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (from.addr != InvariantUtils.GetAddress(from.key) ||
                _nonce != zeroToken.nonces(from.addr) ||
                bound(_actorIndex, 0, 9) == 0) {
                addExpectedError("InvalidSignatureV()");
                addExpectedError("InvalidSignature()");
                addExpectedError("SignerMismatch()");
            }
            if (block.timestamp > _deadline) addExpectedError("SignatureExpired(uint256,uint256)");
            expectedError(_err);
        }
    }

    function mint(
        uint256 _actorIndex,
        uint256 _recipientIndex,
        uint256 _amount
    ) public resetErrors leap(_actorIndex) useRandomMsgSenderWeighted(_actorIndex, zeroToken.standardGovernor(), 75) {
        InvariantUtils.Actor memory recipient = actors[bound(_recipientIndex, 0, actors.length - 1)];
        _amount = bound(_amount, 0, MAX_UINT240);

        startGas();
        try zeroToken.mint(recipient.addr, _amount) {
            stopGas();

            if (actor.addr != standardGovernorActor.addr) {
                standardGovernorDeployerViolationCount++;
            }
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (actor.addr != standardGovernorActor.addr) addExpectedError("NotStandardGovernor()");
            if (MAX_UINT240 < zeroToken.balanceOf(recipient.addr) + _amount ||
                MAX_UINT240 < zeroToken.totalSupply() + _amount) {
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
            }
            if(_amount == 0) addExpectedError("InsufficientAmount(uint256)");

            expectedError(_err);
        }
    }

    function delegateBySig(
        uint256 _actorIndex,
        uint256 _delegatee,
        uint256 _nonce,
        uint256 _expiry
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory signer = actors[bound(_actorIndex, 0, actors.length - 1)];
        InvariantUtils.Actor memory delegatee = actors[bound(_delegatee, 0, actors.length - 1)];
        _expiry = bound(_expiry, BASE_TIMESTAMP, block.timestamp * 4);
        _nonce = bound(
            _nonce,
            (zeroToken.nonces(signer.addr) > 0) ? zeroToken.nonces(signer.addr) - 1 : 0,
            zeroToken.nonces(signer.addr) + 1
        );

        { // fix stack too deep
            bytes32 digest = InvariantUtils.GetDelegateDigest(
                IToken(address(zeroToken)),
                delegatee.addr,
                _nonce,
                _expiry
            );
            (sign.v, sign.r, sign.s) = vm.sign(signer.key, digest);
        }

        // 10% of the time release a signature chaos monkey
        if (bound(_actorIndex, 0, 9) == 0)  {
            sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
            sign.s = bytes32(_actorIndex);
        }

        startGas();
        try zeroToken.delegateBySig(
            delegatee.addr,
            _nonce,
            _expiry,
            sign.v,
            sign.r,
            sign.s
        ) {
            stopGas();

            // success
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (signer.addr != InvariantUtils.GetAddress(signer.key) ||
                _nonce != zeroToken.nonces(signer.addr) ||
                bound(_actorIndex, 0, 9) == 0) {
                addExpectedError("InvalidSignatureV()");
                addExpectedError("InvalidSignature()");
                addExpectedError("SignerMismatch()");
                addExpectedError("InvalidAccountNonce(uint256,uint256)");
            }
            if (block.timestamp > _expiry) addExpectedError("SignatureExpired(uint256,uint256)");
            expectedError(_err);
        }
    }

    function delegateBySigWithSignature(
        uint256 _actorIndex,
        uint256 _delegatee,
        uint256 _nonce,
        uint256 _expiry
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory signer = actors[bound(_actorIndex, 0, actors.length - 1)];
        InvariantUtils.Actor memory delegatee = actors[bound(_delegatee, 0, actors.length - 1)];
        _expiry = bound(_expiry, BASE_TIMESTAMP, block.timestamp * 4);
        _nonce = bound(
            _nonce,
            (zeroToken.nonces(signer.addr) > 0) ? zeroToken.nonces(signer.addr) - 1 : 0,
            zeroToken.nonces(signer.addr) + 1
        );

        { // fix stack too deep
            bytes32 digest = InvariantUtils.GetDelegateDigest(
                IToken(address(zeroToken)),
                delegatee.addr,
                _nonce,
                _expiry
            );
            (sign.v, sign.r, sign.s) = vm.sign(signer.key, digest);
        }

        // 10% of the time release a signature chaos monkey
        if (bound(_actorIndex, 0, 9) == 0)  {
            sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
            sign.s = bytes32(_actorIndex);
        }

        bytes memory signature = abi.encodePacked(
            sign.r,
            sign.s,
            sign.v
        );

        startGas();
        try zeroToken.delegateBySig(
            signer.addr,
            delegatee.addr,
            _nonce,
            _expiry,
            signature
        ) {
            stopGas();

            // success
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (signer.addr != InvariantUtils.GetAddress(signer.key) ||
                _nonce != zeroToken.nonces(signer.addr) ||
                bound(_actorIndex, 0, 9) == 0) {
                addExpectedError("InvalidSignatureV()");
                addExpectedError("InvalidSignature()");
                addExpectedError("SignerMismatch()");
                addExpectedError("InvalidAccountNonce(uint256,uint256)");
            }
            if (block.timestamp > _expiry) addExpectedError("SignatureExpired(uint256,uint256)");
            expectedError(_err);
        }
    }

    function delegate(
        uint256 _actorIndex,
        uint256 _delegatee
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        InvariantUtils.Actor memory delegatee = actors[bound(_delegatee, 0, actors.length - 1)];

        startGas();
        try zeroToken.delegate(delegatee.addr) {
            stopGas();

            // success
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            expectedError(_err);
        }
    }
}

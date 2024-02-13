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

import { VmSafe } from "forge-std/Vm.sol";
import {console, console2} from "forge-std/Test.sol";

import { IERC20 } from "../interfaces/IERC20.sol";
import { IERC5805 } from "../interfaces/IERC5805.sol";

interface IToken is IERC20, IERC5805 {
    function CANCEL_AUTHORIZATION_TYPEHASH() external view returns (bytes32);

    // no idea why this isn't in the IERC5805 interface
    function pastBalanceOf(address, uint256) external view returns (uint256);
    function pastDelegates(address, uint256) external view returns (address);
}

library InvariantUtils {
    VmSafe private constant vm = VmSafe(address(uint160(uint256(keccak256("hevm cheat code")))));

    bytes32 public constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    struct Actor {
        address addr;
        uint256 key;
    }

    struct Signature {
        uint8   v;
        bytes32 r;
        bytes32 s;
    }

    function trim(
        string calldata _str,
        uint _start,
        uint _end
    ) external pure returns(string memory) {
        if (bytes(_str).length < _start) {
            return "";
        }

        return _str[_start:_end];
    }

    // given a private key, returns the address
    function GetAddress(uint256 _key) public pure returns (address addr) {
        Signature memory sig;

        // sign a message with the key and use ecrecover to extract the address
        (sig.v, sig.r, sig.s) = vm.sign(_key, keccak256(abi.encodePacked("my voice is my passport")));
        addr = ecrecover(keccak256(abi.encodePacked("my voice is my passport")), sig.v, sig.r, sig.s);
    }

    function removeArrayElement(bytes32[] storage _arr, uint256 _idx) public {
         require(_idx < _arr.length, "Index out of bounds");

         _arr[_idx] = _arr[_arr.length - 1];
         _arr.pop();
     }


    // Returns an ERC-2612 `permit` digest for the `owner` to sign
    function GetPermitDigest(
        IToken _asset,
        address _owner,
        address _spender,
        uint256 _value,
        uint256 _nonce,
        uint256 _deadline
    ) public view returns (bytes32 _digest) {
        _digest = keccak256(
            abi.encodePacked(
                '\x19\x01',
                _asset.DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        PERMIT_TYPEHASH,
                        _owner,
                        _spender,
                        _value,
                        _nonce,
                        _deadline
                    )
                )
            )
        );
    }

    // Returns an ERC-3009 digest for the '_from' to sign
    function Get3009Digest(
        IToken _asset,
        address _from,
        address _to,
        uint256 _value,
        uint256 _validBefore,
        uint256 _validAfter,
        bytes32 _nonce,
        bytes32 _typehash
    ) public view returns (bytes32 _digest) {
        _digest = keccak256(
            abi.encodePacked(
                '\x19\x01',
                _asset.DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        _typehash,
                        _from,
                        _to,
                        _value,
                        _validBefore,
                        _validAfter,
                        _nonce
                    )
                )
            )
        );
    }

    function Get3009CancelDigest(
        IToken _asset,
        address _authorizer,
        bytes32 _nonce
    ) public view returns (bytes32 _digest) {
        _digest = keccak256(
            abi.encodePacked(
                '\x19\x01',
                _asset.DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        _asset.CANCEL_AUTHORIZATION_TYPEHASH(),
                        _authorizer,
                        _nonce
                    )
                )
            )
        );
    }

    function GetDelegateDigest(
        IToken _asset,
        address _delegatee,
        uint256 _nonce,
        uint256 _expiry
    ) public view returns (bytes32 _digest) {
        _digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                _asset.DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        _asset.DELEGATION_TYPEHASH(),
                        _delegatee,
                        _nonce,
                        _expiry
                    )
                )
            )
        );
    }
}

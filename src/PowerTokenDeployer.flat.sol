// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.23;

/**
 * @title A helper contract to get the address of a contract deployed by aan account with a given nonce.
 * @dev   See the following sources for very similar implementations:
 *          - https://github.com/foundry-rs/forge-std/blob/914702ae99c92fcc41db5128ae57d24a11be4a39/src/Script.sol
 *          - https://github.com/foundry-rs/forge-std/blob/578968243529db44acffcb802196ccab9b54db88/src/StdUtils.sol#L90
 *          - https://github.com/SoulWallet/soul-wallet-contract/blob/develop/script/DeployHelper.sol#L133
 *          - https://github.com/nomoixyz/vulcan/blob/f67740f8a9c846a543aebf29433ad69c3f0ff337/src/_internal/Accounts.sol#L118
 *          - https://github.com/chainlight-io/publications/blob/887d6fe1a4f53573de6b89dbecba0c91b091dba2/ctf-writeups/paradigm2023/dropper/Solve.s.sol#L29
 *          - https://github.com/HerodotusDev/herodotus-evm/blob/a0e9c8be1a17838633d3dcdd54b72682f7654abd/src/lib/CREATE.sol#L5
 *          - https://github.com/Polymarket/ctf-exchange/blob/2745c3017400dbc1925711005fe76b018b999155/src/dev/util/Predictor.sol#L9
 *          - https://github.com/delegatexyz/delegate-market/blob/2418182fe81491114370287412926b57c1ddbd94/script/ComputeAddress.s.sol#L5
 *        Note that this implementation, as do many others, assumes an account does not have a nonce greater than 0xffffffff.
 *        If this is not the case, the address of the contract deployed by the account with the given nonce will be incorrect.
 */
library ContractHelper {
    /**
     * @notice Returns the expected address of a contract deployed by `account_` with transaction count `nonce_`.
     * @param  account_  The address of the account deploying a contract.
     * @param  nonce_    The nonce used in the deployment transaction.
     * @return contract_ The expected address of the deployed contract.
     */
    function getContractFrom(address account_, uint256 nonce_) internal pure returns (address contract_) {
        return
            address(
                uint160(
                    uint256(
                        keccak256(
                            nonce_ == 0x00
                                ? abi.encodePacked(bytes1(0xd6), bytes1(0x94), account_, bytes1(0x80))
                                : nonce_ <= 0x7f
                                ? abi.encodePacked(bytes1(0xd6), bytes1(0x94), account_, uint8(nonce_))
                                : nonce_ <= 0xff
                                ? abi.encodePacked(bytes1(0xd7), bytes1(0x94), account_, bytes1(0x81), uint8(nonce_))
                                : nonce_ <= 0xffff
                                ? abi.encodePacked(bytes1(0xd8), bytes1(0x94), account_, bytes1(0x82), uint16(nonce_))
                                : nonce_ <= 0xffffff
                                ? abi.encodePacked(bytes1(0xd9), bytes1(0x94), account_, bytes1(0x83), uint24(nonce_))
                                : abi.encodePacked(bytes1(0xda), bytes1(0x94), account_, bytes1(0x84), uint32(nonce_))
                        )
                    )
                )
            );
    }
}

/// @title A Deterministic deployer of contracts using CREATE.
interface IDeployer {
    /******************************************************************************************************************\
    |                                               View/Pure Functions                                                |
    \******************************************************************************************************************/

    /// @notice Returns the nonce used to pre deterministically compute the address of the next deployed contract.
    function nonce() external view returns (uint256);

    /// @notice Returns the address of the last contract deployed by this contract.
    function lastDeploy() external view returns (address);

    /// @notice Returns the address of the next contract this contract will deploy.
    function nextDeploy() external view returns (address);
}

/// @title A Deterministic deployer of Power Token contracts using CREATE.
interface IPowerTokenDeployer is IDeployer {
    /******************************************************************************************************************\
    |                                                      Errors                                                      |
    \******************************************************************************************************************/

    /// @notice Revert message when the Vault specified in the constructor is address(0).
    error InvalidVaultAddress();

    /// @notice Revert message when the Zero Governor specified in the constructor is address(0).
    error InvalidZeroGovernorAddress();

    /// @notice Revert message when the caller is not the Zero Governor.
    error NotZeroGovernor();

    /******************************************************************************************************************\
    |                                              Interactive Functions                                               |
    \******************************************************************************************************************/

    /**
     * @notice Deploys a new instance of a Power Token.
     * @param  bootstrapToken   The address of some token to bootstrap from.
     * @param  standardGovernor The address of some Standard Governor.
     * @param  cashToken        The address of some Cash Token.
     * @return The address of the deployed Emergency Governor.
     */
    function deploy(address bootstrapToken, address standardGovernor, address cashToken) external returns (address);

    /******************************************************************************************************************\
    |                                               View/Pure Functions                                                |
    \******************************************************************************************************************/

    /// @notice Returns the address of the Vault.
    function vault() external view returns (address);

    /// @notice Returns the address of the Zero Governor.
    function zeroGovernor() external view returns (address);
}

/// @title Interface of the ERC20 standard as needed by ERC20Helper.
interface IERC20Like {

    function approve(address spender_, uint256 amount_) external returns (bool success_);

    function transfer(address recipient_, uint256 amount_) external returns (bool success_);

    function transferFrom(address owner_, address recipient_, uint256 amount_) external returns (bool success_);

}

/**
 * @title Small Library to standardize erc20 token interactions.
 */
library ERC20Helper {

    /**************************************************************************************************************************************/
    /*** Internal Functions                                                                                                             ***/
    /**************************************************************************************************************************************/

    function transfer(address token_, address to_, uint256 amount_) internal returns (bool success_) {
        return _call(token_, abi.encodeWithSelector(IERC20Like.transfer.selector, to_, amount_));
    }

    function transferFrom(address token_, address from_, address to_, uint256 amount_) internal returns (bool success_) {
        return _call(token_, abi.encodeWithSelector(IERC20Like.transferFrom.selector, from_, to_, amount_));
    }

    function approve(address token_, address spender_, uint256 amount_) internal returns (bool success_) {
        // If setting approval to zero fails, return false.
        if (!_call(token_, abi.encodeWithSelector(IERC20Like.approve.selector, spender_, uint256(0)))) return false;

        // If `amount_` is zero, return true as the previous step already did this.
        if (amount_ == uint256(0)) return true;

        // Return the result of setting the approval to `amount_`.
        return _call(token_, abi.encodeWithSelector(IERC20Like.approve.selector, spender_, amount_));
    }

    function _call(address token_, bytes memory data_) private returns (bool success_) {
        if (token_.code.length == uint256(0)) return false;

        bytes memory returnData;
        ( success_, returnData ) = token_.call(data_);

        return success_ && (returnData.length == uint256(0) || abi.decode(returnData, (bool)));
    }

}

/**
 * @title Library to perform safe math operations on uint types
 * @author M^0 Labs
 */
library UIntMath {
    /// @notice Emitted when a passed value is greater than the maximum value of uint16.
    error InvalidUInt16();

    /// @notice Emitted when a passed value is greater than the maximum value of uint40.
    error InvalidUInt40();

    /// @notice Emitted when a passed value is greater than the maximum value of uint48.
    error InvalidUInt48();

    /// @notice Emitted when a passed value is greater than the maximum value of uint112.
    error InvalidUInt112();

    /// @notice Emitted when a passed value is greater than the maximum value of uint128.
    error InvalidUInt128();

    /// @notice Emitted when a passed value is greater than the maximum value of uint240.
    error InvalidUInt240();

    /**
     * @notice Casts a given uint256 value to a uint16, ensuring that it is less than or equal to the maximum uint16 value.
     * @param  n The value to check.
     * @return The value casted to uint16.
     */
    function safe16(uint256 n) internal pure returns (uint16) {
        if (n > type(uint16).max) revert InvalidUInt16();
        return uint16(n);
    }

    /**
     * @notice Casts a given uint256 value to a uint40, ensuring that it is less than or equal to the maximum uint40 value.
     * @param  n The value to check.
     * @return The value casted to uint40.
     */
    function safe40(uint256 n) internal pure returns (uint40) {
        if (n > type(uint40).max) revert InvalidUInt40();
        return uint40(n);
    }

    /**
     * @notice Casts a given uint256 value to a uint48, ensuring that it is less than or equal to the maximum uint48 value.
     * @param  n The value to check.
     * @return The value casted to uint48.
     */
    function safe48(uint256 n) internal pure returns (uint48) {
        if (n > type(uint48).max) revert InvalidUInt48();
        return uint48(n);
    }

    /**
     * @notice Casts a given uint256 value to a uint112, ensuring that it is less than or equal to the maximum uint112 value.
     * @param  n The value to check.
     * @return The value casted to uint112.
     */
    function safe112(uint256 n) internal pure returns (uint112) {
        if (n > type(uint112).max) revert InvalidUInt112();
        return uint112(n);
    }

    /**
     * @notice Casts a given uint256 value to a uint128, ensuring that it is less than or equal to the maximum uint128 value.
     * @param  n The value to check.
     * @return The value casted to uint128.
     */
    function safe128(uint256 n) internal pure returns (uint128) {
        if (n > type(uint128).max) revert InvalidUInt128();
        return uint128(n);
    }

    /**
     * @notice Casts a given uint256 value to a uint240, ensuring that it is less than or equal to the maximum uint240 value.
     * @param  n The value to check.
     * @return The value casted to uint240.
     */
    function safe240(uint256 n) internal pure returns (uint240) {
        if (n > type(uint240).max) revert InvalidUInt240();
        return uint240(n);
    }

    /**
     * @notice Limits a given uint256 value to the maximum uint32 value.
     * @param  n The value to check.
     * @return The value limited to within uint32 bounds.
     */
    function bound32(uint256 n) internal pure returns (uint32) {
        return uint32(min256(n, uint256(type(uint32).max)));
    }

    /**
     * @notice Limits a given uint256 value to the maximum uint112 value.
     * @param  n The value to check.
     * @return The value limited to within uint112 bounds.
     */
    function bound112(uint256 n) internal pure returns (uint112) {
        return uint112(min256(n, uint256(type(uint112).max)));
    }

    /**
     * @notice Limits a given uint256 value to the maximum uint240 value.
     * @param  n The value to check.
     * @return The value limited to within uint240 bounds.
     */
    function bound240(uint256 n) internal pure returns (uint240) {
        return uint240(min256(n, uint256(type(uint240).max)));
    }

    /**
     * @notice Compares two uint40 values and returns the larger one.
     * @param  a_  Value to check.
     * @param  b_  Value to check.
     * @return The larger value.
     */
    function max40(uint40 a_, uint40 b_) internal pure returns (uint40) {
        return a_ > b_ ? a_ : b_;
    }

    /**
     * @notice Compares two uint32 values and returns the lesser one.
     * @param  a_  Value to check.
     * @param  b_  Value to check.
     * @return The lesser value.
     */
    function min32(uint32 a_, uint32 b_) internal pure returns (uint32) {
        return a_ < b_ ? a_ : b_;
    }

    /**
     * @notice Compares two uint40 values and returns the lesser one.
     * @param  a_  Value to check.
     * @param  b_  Value to check.
     * @return The lesser value.
     */
    function min40(uint40 a_, uint40 b_) internal pure returns (uint40) {
        return a_ < b_ ? a_ : b_;
    }

    /**
     * @notice Compares two uint240 values and returns the lesser one.
     * @param  a_  Value to check.
     * @param  b_  Value to check.
     * @return The lesser value.
     */
    function min240(uint240 a_, uint240 b_) internal pure returns (uint240) {
        return a_ < b_ ? a_ : b_;
    }

    /**
     * @notice Compares two uint112 values and returns the lesser one.
     * @param  a_  Value to check.
     * @param  b_  Value to check.
     * @return The lesser value.
     */
    function min112(uint112 a_, uint112 b_) internal pure returns (uint112) {
        return a_ < b_ ? a_ : b_;
    }

    /**
     * @notice Compares two uint256 values and returns the lesser one.
     * @param  a_  Value to check.
     * @param  b_  Value to check.
     * @return The lesser value.
     */
    function min256(uint256 a_, uint256 b_) internal pure returns (uint256) {
        return a_ < b_ ? a_ : b_;
    }

    /**
     * @notice Compares two uint40 values and returns the lesser one while ignoring zero values.
     * @param  a_  Value to check.
     * @param  b_  Value to check.
     * @return The lesser value.
     */
    function min40IgnoreZero(uint40 a_, uint40 b_) internal pure returns (uint40) {
        return a_ == 0 ? b_ : (b_ == 0 ? a_ : min40(a_, b_));
    }
}

/// @notice Defines epochs as 15 days away from 'The Merge' timestamp.
/// @dev    Allows for a `uint16` epoch up to timestamp 86,595,288,162 (i.e. Thu, Feb 05, Year 4714, 06:42:42 GMT).
library PureEpochs {
    /// @notice The timestamp of The Merge block.
    uint40 internal constant _MERGE_TIMESTAMP = 1_663_224_162;

    /// @notice The approximate target of seconds an epoch should endure.
    uint40 internal constant _EPOCH_PERIOD = 15 days;

    function currentEpoch() internal view returns (uint16 currentEpoch_) {
        return uint16(((block.timestamp - _MERGE_TIMESTAMP) / _EPOCH_PERIOD) + 1); // Epoch at `_MERGE_TIMESTAMP` is 1.
    }

    function timeElapsedInCurrentEpoch() internal view returns (uint40 time_) {
        return uint40(block.timestamp) - getTimestampOfEpochStart(currentEpoch());
    }

    function timeRemainingInCurrentEpoch() internal view returns (uint40 time_) {
        return getTimestampOfEpochEnd(currentEpoch()) - uint40(block.timestamp);
    }

    function getTimeUntilEpochStart(uint16 epoch) internal view returns (uint40 time_) {
        return getTimestampOfEpochStart(epoch) - uint40(block.timestamp);
    }

    function getTimeUntilEpochEnds(uint16 epoch) internal view returns (uint40 time_) {
        return getTimestampOfEpochEnd(epoch) - uint40(block.timestamp);
    }

    function getTimeSinceEpochStart(uint16 epoch) internal view returns (uint40 time_) {
        return uint40(block.timestamp) - getTimestampOfEpochStart(epoch);
    }

    function getTimeSinceEpochEnd(uint16 epoch) internal view returns (uint40 time_) {
        return uint40(block.timestamp) - getTimestampOfEpochEnd(epoch);
    }

    function getTimestampOfEpochStart(uint16 epoch) internal pure returns (uint40 timestamp_) {
        return _MERGE_TIMESTAMP + (epoch - 1) * _EPOCH_PERIOD;
    }

    function getTimestampOfEpochEnd(uint16 epoch) internal pure returns (uint40 timestamp_) {
        return getTimestampOfEpochStart(epoch + 1);
    }
}

/// @title ERC20 Token Standard.
/// @dev   The interface as defined by EIP-20: https://eips.ethereum.org/EIPS/eip-20
interface IERC20 {
    /******************************************************************************************************************\
    |                                                      Events                                                      |
    \******************************************************************************************************************/

    /**
     * @notice Emitted when `spender` has been approved for `amount` of the token balance of `account`.
     * @param  account The address of the account.
     * @param  spender The address of the spender being approved for the allowance.
     * @param  amount  The amount of the allowance being approved.
     */
    event Approval(address indexed account, address indexed spender, uint256 amount);

    /**
     * @notice Emitted when `amount` tokens is transferred from `sender` to `recipient`.
     * @param  sender    The address of the sender who's token balance is decremented.
     * @param  recipient The address of the recipient who's token balance is incremented.
     * @param  amount    The amount of tokens being transferred.
     */
    event Transfer(address indexed sender, address indexed recipient, uint256 amount);

    /******************************************************************************************************************\
    |                                             Interactive Functions                                                |
    \******************************************************************************************************************/

    /**
     * @notice Allows a calling account to approve `spender` to spend up to `amount` of its token balance.
     * @param  spender The address of the account being allowed to spend up to the allowed amount.
     * @param  amount  The amount of the allowance being approved.
     * @return Whether or not the approval was successful.
     */
    function approve(address spender, uint256 amount) external returns (bool);

    /**
     * @notice Allows a calling account to transfer `amount` tokens to `recipient`.
     * @param  recipient The address of the recipient who's token balance will be incremented.
     * @param  amount    The amount of tokens being transferred.
     * @return Whether or not the transfer was successful.
     */
    function transfer(address recipient, uint256 amount) external returns (bool);

    /**
     * @notice Allows a calling account to transfer `amount` tokens from `sender`, with allowance, to a `recipient`.
     * @param  sender    The address of the sender who's token balance will be decremented.
     * @param  recipient The address of the recipient who's token balance will be incremented.
     * @param  amount    The amount of tokens being transferred.
     * @return Whether or not the transfer was successful.
     */
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);

    /******************************************************************************************************************\
    |                                              View/Pure Functions                                                 |
    \******************************************************************************************************************/

    /**
     * @notice Returns the allowance `spender` is allowed to spend on behalf of `account`.
     * @param  account The address of the account who's token balance `spender` is allowed to spend.
     * @param  spender The address of an account allowed to spend on behalf of `account`.
     * @return The amount `spender` can spend on behalf of `account`.
     */
    function allowance(address account, address spender) external view returns (uint256);

    /**
     * @notice Returns the token balance of `account`.
     * @param  account The address of some account.
     * @return The token balance of `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /// @notice Returns the number of decimals UIs should assume all amounts have.
    function decimals() external view returns (uint8);

    /// @notice Returns the name of the contract/token.
    function name() external view returns (string memory);

    /// @notice Returns the symbol of the token.
    function symbol() external view returns (string memory);

    /// @notice Returns the current total supply of the token.
    function totalSupply() external view returns (uint256);
}

/// @title Typed structured data hashing and signing via EIP-712.
/// @dev   The interface as defined by EIP-712: https://eips.ethereum.org/EIPS/eip-712
interface IERC712 {
    /// @notice Revert message when an invalid signature is detected.
    error InvalidSignature();

    /// @notice Revert message when a signature with invalid length is detected.
    error InvalidSignatureLength();

    /**
     * @notice Revert message when a signature is being used beyond its deadline (i.e. expiry).
     * @param  deadline  The deadline of the signature.
     * @param  timestamp The current timestamp.
     */
    error SignatureExpired(uint256 deadline, uint256 timestamp);

    /// @notice Revert message when a recovered signer does not match the account being purported to have signed.
    error SignerMismatch();

    /// @notice Returns the EIP712 domain separator used in the encoding of a signed digest.
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}

/// @title Stateful Extension for EIP-712 typed structured data hashing and signing with nonces.
interface IStatefulERC712 is IERC712 {
    /**
     * @notice Revert message when a signing account's nonce is reused by a signature.
     * @param  nonce         The nonce used in the signature.
     * @param  expectedNonce The expected nonce to be used in a signature by the signing account.
     */
    error ReusedNonce(uint256 nonce, uint256 expectedNonce);

    /**
     * @notice Returns the next nonce to be used in a signature by `account`.
     * @param  account The address of some account.
     * @return nonce   The next nonce to be used in a signature by `account`.
     */
    function nonces(address account) external view returns (uint256 nonce);
}

/// @title Transfer via signed authorization following EIP-3009 standard.
/// @dev   The interface as defined by EIP-3009: https://eips.ethereum.org/EIPS/eip-3009
interface IERC3009 is IStatefulERC712 {
    /**
     * @notice Emitted when an authorization has been used.
     * @param  authorizer Authorizer's address.
     * @param  nonce      Nonce of the used authorization.
     */
    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);

    /**
     * @notice Emitted when an authorization has been canceled.
     * @param  authorizer Authorizer's address.
     * @param  nonce      Nonce of the canceled authorization.
     */
    event AuthorizationCanceled(address indexed authorizer, bytes32 indexed nonce);

    /**
     * @notice Emitted when an authorization has already been used.
     * @param  authorizer Authorizer's address.
     * @param  nonce      Nonce of the used authorization.
     */
    error AuthorizationAlreadyUsed(address authorizer, bytes32 nonce);

    /**
     * @notice Emitted when an authorization is not yet valid.
     * @param  timestamp  Timestamp at which the transaction was submitted.
     * @param  validAfter Timestamp after which the authorization will be valid.
     */
    error AuthorizationNotYetValid(uint256 timestamp, uint256 validAfter);

    /**
     * @notice Emitted when an authorization is expired.
     * @param  timestamp   Timestamp at which the transaction was submitted.
     * @param  validBefore Timestamp before which the authorization would have been valid.
     */
    error AuthorizationExpired(uint256 timestamp, uint256 validBefore);

    /**
     * @notice Emitted when the caller of `receiveWithAuthorization` is not the payee.
     * @param  caller Caller's address.
     * @param  payee  Payee's address.
     */
    error CallerMustBePayee(address caller, address payee);

    /**
     * @notice Returns the state of an authorization.
     * @dev    Nonces are randomly generated 32-byte data unique to the authorizer's address
     * @param  authorizer Authorizer's address.
     * @param  nonce      Nonce of the authorization.
     * @return True if the nonce is used.
     */
    function authorizationState(address authorizer, bytes32 nonce) external view returns (bool);

    /**
     * @notice Execute a transfer with a signed authorization.
     * @param  from        Payer's address (Authorizer).
     * @param  to          Payee's address.
     * @param  value       Amount to be transferred.
     * @param  validAfter  The time after which this is valid (unix time).
     * @param  validBefore The time before which this is valid (unix time).
     * @param  nonce       Unique nonce.
     * @param  signature   A byte array ECDSA/secp256k1 signature (encoded r, s, v).
     */
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes memory signature
    ) external;

    /**
     * @notice Execute a transfer with a signed authorization.
     * @param  from        Payer's address (Authorizer).
     * @param  to          Payee's address.
     * @param  value       Amount to be transferred.
     * @param  validAfter  The time after which this is valid (unix time).
     * @param  validBefore The time before which this is valid (unix time).
     * @param  nonce       Unique nonce.
     * @param  r           An ECDSA/secp256k1 signature parameter.
     * @param  vs          An ECDSA/secp256k1 short signature parameter.
     */
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes32 r,
        bytes32 vs
    ) external;

    /**
     * @notice Execute a transfer with a signed authorization.
     * @param  from        Payer's address (Authorizer).
     * @param  to          Payee's address.
     * @param  value       Amount to be transferred.
     * @param  validAfter  The time after which this is valid (unix time).
     * @param  validBefore The time before which this is valid (unix time).
     * @param  nonce       Unique nonce.
     * @param  v           v of the signature.
     * @param  r           r of the signature.
     * @param  s           s of the signature.
     */
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;

    /**
     * @notice Receive a transfer with a signed authorization from the payer.
     * @dev    This has an additional check to ensure that the payee's address matches
     *         the caller of this function to prevent front-running attacks.
     *         (See security considerations)
     * @param  from        Payer's address (Authorizer).
     * @param  to          Payee's address.
     * @param  value       Amount to be transferred.
     * @param  validAfter  The time after which this is valid (unix time).
     * @param  validBefore The time before which this is valid (unix time).
     * @param  nonce       Unique nonce.
     * @param  signature   A byte array ECDSA/secp256k1 signature (encoded r, s, v).
     */
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes memory signature
    ) external;

    /**
     * @notice Receive a transfer with a signed authorization from the payer.
     * @dev    This has an additional check to ensure that the payee's address matches
     *         the caller of this function to prevent front-running attacks.
     *         (See security considerations)
     * @param  from        Payer's address (Authorizer).
     * @param  to          Payee's address.
     * @param  value       Amount to be transferred.
     * @param  validAfter  The time after which this is valid (unix time).
     * @param  validBefore The time before which this is valid (unix time).
     * @param  nonce       Unique nonce.
     * @param  r           An ECDSA/secp256k1 signature parameter.
     * @param  vs          An ECDSA/secp256k1 short signature parameter.
     */
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes32 r,
        bytes32 vs
    ) external;

    /**
     * @notice Receive a transfer with a signed authorization from the payer.
     * @dev    This has an additional check to ensure that the payee's address matches
     *         the caller of this function to prevent front-running attacks.
     *         (See security considerations)
     * @param  from        Payer's address (Authorizer).
     * @param  to          Payee's address.
     * @param  value       Amount to be transferred.
     * @param  validAfter  The time after which this is valid (unix time).
     * @param  validBefore The time before which this is valid (unix time).
     * @param  nonce       Unique nonce.
     * @param  v           v of the signature.
     * @param  r           r of the signature.
     * @param  s           s of the signature.
     */
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;

    /**
     * @notice Attempt to cancel an authorization.
     * @param  authorizer Authorizer's address.
     * @param  nonce      Nonce of the authorization.
     * @param  signature  A byte array ECDSA/secp256k1 signature (encoded r, s, v).
     */
    function cancelAuthorization(address authorizer, bytes32 nonce, bytes memory signature) external;

    /**
     * @notice Attempt to cancel an authorization.
     * @param  authorizer Authorizer's address.
     * @param  nonce      Nonce of the authorization.
     * @param  r          An ECDSA/secp256k1 signature parameter.
     * @param  vs         An ECDSA/secp256k1 short signature parameter.
     */
    function cancelAuthorization(address authorizer, bytes32 nonce, bytes32 r, bytes32 vs) external;

    /**
     * @notice Attempt to cancel an authorization.
     * @param  authorizer Authorizer's address.
     * @param  nonce      Nonce of the authorization.
     * @param  v          v of the signature.
     * @param  r          r of the signature.
     * @param  s          s of the signature.
     */
    function cancelAuthorization(address authorizer, bytes32 nonce, uint8 v, bytes32 r, bytes32 s) external;
}

/// @title An ERC20 token extended with EIP-2612 permits for signed approvals (via EIP-712 and with EIP-1271
//         compatibility), and extended with EIP-3009 transfer with authorization (via EIP-712).
/// @dev   The interface as defined by EIP-2612: https://eips.ethereum.org/EIPS/eip-2612
interface IERC20Extended is IERC20, IERC3009 {
    /**
     * @notice Approves `spender` to spend up to `amount` of the token balance of `owner`, via a signature.
     * @param  owner    The address of the account who's token balance is being approved to be spent by `spender`.
     * @param  spender  The address of an account allowed to spend on behalf of `owner`.
     * @param  value    The amount of the allowance being approved.
     * @param  deadline The last block number where the signature is still valid.
     * @param  v        An ECDSA secp256k1 signature parameter (EIP-2612 via EIP-712).
     * @param  r        An ECDSA secp256k1 signature parameter (EIP-2612 via EIP-712).
     * @param  s        An ECDSA secp256k1 signature parameter (EIP-2612 via EIP-712).
     */
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;

    /**
     * @notice Approves `spender` to spend up to `amount` of the token balance of `owner`, via a signature.
     * @param  owner     The address of the account who's token balance is being approved to be spent by `spender`.
     * @param  spender   The address of an account allowed to spend on behalf of `owner`.
     * @param  value     The amount of the allowance being approved.
     * @param  deadline  The last block number where the signature is still valid.
     * @param  signature An arbitrary signature (EIP-712).
     */
    function permit(address owner, address spender, uint256 value, uint256 deadline, bytes memory signature) external;

    /// @notice Returns the EIP712 typehash used in the encoding of the digest for the permit function.
    function PERMIT_TYPEHASH() external view returns (bytes32 typehash);
}

/**
 * @title Contract clock properties.
 * @dev   The interface as defined by EIP-6372: https://eips.ethereum.org/EIPS/eip-6372
 */
interface IERC6372 {
    /// @notice Returns a machine-readable string description of the clock the contract is operating on.
    function CLOCK_MODE() external view returns (string memory);

    /// @notice Returns the current timepoint according to the mode the contract is operating on.
    function clock() external view returns (uint48);
}

/// @title Voting with voting weight tracking and delegation support.
/// @dev   The interface as defined by EIP-5805: https://eips.ethereum.org/EIPS/eip-5805
interface IERC5805 is IStatefulERC712, IERC6372 {
    /******************************************************************************************************************\
    |                                                      Events                                                      |
    \******************************************************************************************************************/

    /**
     * @notice Emitted when `delegator` changes its voting power delegation from `fromDelegatee` to `toDelegatee`.
     * @param  delegator     The address of the account changing its voting power delegation.
     * @param  fromDelegatee The previous account the voting power of `delegator` was delegated to.
     * @param  toDelegatee   The new account the voting power of `delegator` is delegated to.
     */
    event DelegateChanged(address indexed delegator, address indexed fromDelegatee, address indexed toDelegatee);

    /**
     * @notice Emitted when the available voting power of `delegatee` changes from `previousBalance` to `newBalance`.
     * @param  delegatee       The address of the account who's voting power is changed.
     * @param  previousBalance The previous voting power of `delegatee`.
     * @param  newBalance      The new voting power of `delegatee`.
     */
    event DelegateVotesChanged(address indexed delegatee, uint256 previousBalance, uint256 newBalance);

    /******************************************************************************************************************\
    |                                                      Errors                                                      |
    \******************************************************************************************************************/

    /**
     * @notice Revert message when a query for past values is for a timepoint greater or equal to the current clock.
     * @param  timepoint The timepoint being queried.
     * @param  clock     The current timepoint.
     */
    error NotPastTimepoint(uint48 timepoint, uint48 clock);

    /******************************************************************************************************************\
    |                                              Interactive Functions                                               |
    \******************************************************************************************************************/

    /**
     * @notice Allows a calling account to change its voting power delegation to `delegatee`.
     * @param  delegatee The address of the account the caller's voting power will be delegated to.
     */
    function delegate(address delegatee) external;

    /**
     * @notice Changes the signing account's voting power delegation to `delegatee`.
     * @param  delegatee The address of the account the signing account's voting power will be delegated to.
     * @param  expiry    The last block number where the signature is still valid.
     * @param  v         A signature parameter.
     * @param  r         A signature parameter.
     * @param  s         A signature parameter.
     */
    function delegateBySig(address delegatee, uint256 nonce, uint256 expiry, uint8 v, bytes32 r, bytes32 s) external;

    /******************************************************************************************************************\
    |                                               View/Pure Functions                                                |
    \******************************************************************************************************************/

    /// @notice Returns the EIP712 typehash used in the encoding of the digest for the delegateBySig function.
    function DELEGATION_TYPEHASH() external view returns (bytes32);

    /**
     * @notice Returns the delegatee the voting power of `account` is delegated to.
     * @param  account The address of the account that can delegate its voting power.
     * @return The address of the account the voting power of `account` will be delegated to.
     */
    function delegates(address account) external view returns (address);

    /**
     * @notice Returns the total voting power of `account` at a past clock value `timepoint`.
     * @param  account   The address of some account.
     * @param  timepoint The point in time, according to the clock mode the contract is operating on.
     * @return The total voting power of `account` at clock value `timepoint`.
     */
    function getPastVotes(address account, uint256 timepoint) external view returns (uint256);

    /**
     * @notice Returns the total voting power of `account`.
     * @param  account The address of some account.
     * @return The total voting power of `account`.
     */
    function getVotes(address account) external view returns (uint256);
}

/// @title Extension for an ERC5805 token that uses epochs as its clock mode and delegation via IERC1271.
interface IEpochBasedVoteToken is IERC5805, IERC20Extended {
    /******************************************************************************************************************\
    |                                                      Errors                                                      |
    \******************************************************************************************************************/

    /// @notice Revert message when an number being casted to a uint240 exceeds the maximum uint240 value.
    error AmountExceedsUint240();

    /******************************************************************************************************************\
    |                                              Interactive Functions                                               |
    \******************************************************************************************************************/

    /**
     * @notice Changes the voting power delegation for `account` to `delegatee`.
     * @param  account   The purported address of the signing account.
     * @param  delegatee The address the voting power of `account` will be delegated to.
     * @param  nonce     The nonce used for the signature.
     * @param  expiry    The last block number where the signature is still valid.
     * @param  signature A byte array signature.
     */
    function delegateBySig(
        address account,
        address delegatee,
        uint256 nonce,
        uint256 expiry,
        bytes memory signature
    ) external;

    /******************************************************************************************************************\
    |                                               View/Pure Functions                                                |
    \******************************************************************************************************************/

    /**
     * @notice Returns the digest to be signed, via EIP-712, given an internal digest (i.e. hash struct).
     * @param  delegatee The address of the delegatee to delegate to.
     * @param  nonce     The nonce of the account delegating.
     * @param  expiry    The last timestamp at which the signature is still valid.
     * @return The digest to be signed.
     */
    function getDelegationDigest(address delegatee, uint256 nonce, uint256 expiry) external view returns (bytes32);

    /**
     * @notice Returns the token balance of `account` at a past clock value `epoch`.
     * @param  account The address of some account.
     * @param  epoch   The epoch number as a clock value.
     * @return The token balance `account` at `epoch`.
     */
    function pastBalanceOf(address account, uint256 epoch) external view returns (uint256);

    /**
     * @notice Returns the delegatee of `account` at a past clock value `epoch`.
     * @param  account The address of some account.
     * @param  epoch   The epoch number as a clock value.
     * @return The delegatee of the voting power of `account` at `epoch`.
     */
    function pastDelegates(address account, uint256 epoch) external view returns (address);

    /**
     * @notice Returns the total token supply at a past clock value `epoch`.
     * @param  epoch The epoch number as a clock value.
     * @return The total token supply at `epoch`.
     */
    function pastTotalSupply(uint256 epoch) external view returns (uint256);
}

/// @title Extension for an EpochBasedVoteToken token that allows for inflating tokens and voting power.
interface IEpochBasedInflationaryVoteToken is IEpochBasedVoteToken {
    /******************************************************************************************************************\
    |                                                      Errors                                                      |
    \******************************************************************************************************************/

    /// @notice Revert message when trying to mark an account as participated in an epoch where it already participated.
    error AlreadyParticipated();

    /// @notice Revert message when trying to construct contact with inflation above 100%.
    error InflationTooHigh();

    /// @notice Revert message when trying to perform an action not allowed outside of designated voting epochs.
    error NotVoteEpoch();

    /// @notice Revert message when trying to perform an action not allowed during designated voting epochs.
    error VoteEpoch();

    /******************************************************************************************************************\
    |                                               View/Pure Functions                                                |
    \******************************************************************************************************************/

    /**
     * @notice Returns whether `delegatee` has participated in voting during clock value `epoch`.
     * @param  delegatee The address of a delegatee with voting power.
     * @param  epoch     The epoch number as a clock value.
     * @return Whether `delegatee` has participated in voting during `epoch`.
     */
    function hasParticipatedAt(address delegatee, uint256 epoch) external view returns (bool);

    /// @notice Returns the participation inflation rate used to inflate tokens for participation.
    function participationInflation() external view returns (uint16);

    /// @notice Returns 100% in basis point, to be used to correctly ascertain the participation inflation rate.
    function ONE() external pure returns (uint16);
}

/// @title Standard Signature Validation Method for Contracts via EIP-1271.
/// @dev   The interface as defined by EIP-1271: https://eips.ethereum.org/EIPS/eip-1271
interface IERC1271 {
    /**
     * @dev    Returns a specific magic value if the provided signature is valid for the provided digest.
     * @param  digest     Hash of the data purported to have been signed.
     * @param  signature  Signature byte array associated with the digest.
     * @return magicValue Magic value 0x1626ba7e if the signature is valid.
     */
    function isValidSignature(bytes32 digest, bytes memory signature) external view returns (bytes4 magicValue);
}

/// @title A library to handle ECDSA/secp256k1 and ERC1271 signatures, individually or in arbitrarily in combination.
library SignatureChecker {
    enum Error {
        NoError,
        InvalidSignature,
        InvalidSignatureLength,
        InvalidSignatureS,
        InvalidSignatureV,
        SignerMismatch
    }

    /**
     * @dev    Decodes an ECDSA/secp256k1 signature from a byte array to standard v, r, and s parameters.
     * @param  signature A byte array ECDSA/secp256k1 signature.
     * @return v         An ECDSA/secp256k1 signature parameter.
     * @return r         An ECDSA/secp256k1 signature parameter.
     * @return s         An ECDSA/secp256k1 signature parameter.
     */
    function decodeECDSASignature(bytes memory signature) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        // ecrecover takes the signature parameters, and they can be decoded using assembly.
        /// @solidity memory-safe-assembly
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
    }

    /**
     * @dev    Decodes an ECDSA/secp256k1 short signature as defined by EIP2098
     *         from a byte array to standard v, r, and s parameters.
     * @param  signature A byte array ECDSA/secp256k1 short signature.
     * @return r         An ECDSA/secp256k1 signature parameter.
     * @return vs        An ECDSA/secp256k1 short signature parameter.
     */
    function decodeShortECDSASignature(bytes memory signature) internal pure returns (bytes32 r, bytes32 vs) {
        // ecrecover takes the signature parameters, and they can be decoded using assembly.
        /// @solidity memory-safe-assembly
        assembly {
            r := mload(add(signature, 0x20))
            vs := mload(add(signature, 0x40))
        }
    }

    /**
     * @dev    Returns whether a signature is valid (ECDSA/secp256k1 or ERC1271) for a signer and digest.
     * @dev    Signatures must not be used as unique identifiers since the `ecrecover` EVM opcode
     *         allows for malleable (non-unique) signatures.
     *         See https://github.com/OpenZeppelin/openzeppelin-contracts/security/advisories/GHSA-4h98-2769-gh6h
     * @param  signer    The address of the account purported to have signed.
     * @param  digest    The hash of the data that was signed.
     * @param  signature A byte array signature.
     * @return isValid   Whether the signature is valid.
     */
    function isValidSignature(
        address signer,
        bytes32 digest,
        bytes memory signature
    ) internal view returns (bool isValid) {
        return isValidECDSASignature(signer, digest, signature) || isValidERC1271Signature(signer, digest, signature);
    }

    /**
     * @dev    Returns whether an ECDSA/secp256k1 signature is valid for a signer and digest.
     * @param  signer    The address of the account purported to have signed.
     * @param  digest    The hash of the data that was signed.
     * @param  signature A byte array ECDSA/secp256k1 signature (encoded r, s, v).
     * @return isValid   Whether the signature is valid.
     */
    function isValidECDSASignature(
        address signer,
        bytes32 digest,
        bytes memory signature
    ) internal pure returns (bool isValid) {
        if (signature.length == 64) {
            (bytes32 r, bytes32 vs) = decodeShortECDSASignature(signature);
            return isValidECDSASignature(signer, digest, r, vs);
        }

        return validateECDSASignature(signer, digest, signature) == Error.NoError;
    }

    /**
     * @dev    Returns whether an ECDSA/secp256k1 short signature is valid for a signer and digest.
     * @param  signer  The address of the account purported to have signed.
     * @param  digest  The hash of the data that was signed.
     * @param  r       An ECDSA/secp256k1 signature parameter.
     * @param  vs      An ECDSA/secp256k1 short signature parameter.
     * @return isValid Whether the signature is valid.
     */
    function isValidECDSASignature(
        address signer,
        bytes32 digest,
        bytes32 r,
        bytes32 vs
    ) internal pure returns (bool isValid) {
        return validateECDSASignature(signer, digest, r, vs) == Error.NoError;
    }

    /**
     * @dev    Returns whether an ECDSA/secp256k1 signature is valid for a signer and digest.
     * @param  signer  The address of the account purported to have signed.
     * @param  digest  The hash of the data that was signed.
     * @param  v       An ECDSA/secp256k1 signature parameter.
     * @param  r       An ECDSA/secp256k1 signature parameter.
     * @param  s       An ECDSA/secp256k1 signature parameter.
     * @return isValid Whether the signature is valid.
     */
    function isValidECDSASignature(
        address signer,
        bytes32 digest,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (bool isValid) {
        return validateECDSASignature(signer, digest, v, r, s) == Error.NoError;
    }

    /**
     * @dev    Returns whether an ERC1271 signature is valid for a signer and digest.
     * @param  signer    The address of the account purported to have signed.
     * @param  digest    The hash of the data that was signed.
     * @param  signature A byte array ERC1271 signature.
     * @return isValid   Whether the signature is valid.
     */
    function isValidERC1271Signature(
        address signer,
        bytes32 digest,
        bytes memory signature
    ) internal view returns (bool isValid) {
        (bool success, bytes memory result) = signer.staticcall(
            abi.encodeCall(IERC1271.isValidSignature, (digest, signature))
        );

        return
            success &&
            result.length >= 32 &&
            abi.decode(result, (bytes32)) == bytes32(IERC1271.isValidSignature.selector);
    }

    /**
     * @dev    Returns the signer of an ECDSA/secp256k1 signature for some digest.
     * @param  digest    The hash of the data that was signed.
     * @param  signature A byte array ECDSA/secp256k1 signature.
     * @return error     An error, if any, that occurred during the signer recovery.
     * @return signer    The address of the account recovered form the signature (0 if error).
     */
    function recoverECDSASigner(
        bytes32 digest,
        bytes memory signature
    ) internal pure returns (Error error, address signer) {
        if (signature.length != 65) return (Error.InvalidSignatureLength, address(0));

        (uint8 v, bytes32 r, bytes32 s) = decodeECDSASignature(signature);

        return recoverECDSASigner(digest, v, r, s);
    }

    /**
     * @dev    Returns the signer of an ECDSA/secp256k1 short signature for some digest.
     * @dev    See https://eips.ethereum.org/EIPS/eip-2098
     * @param  digest The hash of the data that was signed.
     * @param  r      An ECDSA/secp256k1 signature parameter.
     * @param  vs     An ECDSA/secp256k1 short signature parameter.
     * @return error  An error, if any, that occurred during the signer recovery.
     * @return signer The address of the account recovered form the signature (0 if error).
     */
    function recoverECDSASigner(
        bytes32 digest,
        bytes32 r,
        bytes32 vs
    ) internal pure returns (Error error, address signer) {
        unchecked {
            // We do not check for an overflow here since the shift operation results in 0 or 1.
            uint8 v = uint8((uint256(vs) >> 255) + 27);
            bytes32 s = vs & bytes32(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
            return recoverECDSASigner(digest, v, r, s);
        }
    }

    /**
     * @dev    Returns the signer of an ECDSA/secp256k1 signature for some digest.
     * @param  digest The hash of the data that was signed.
     * @param  v      An ECDSA/secp256k1 signature parameter.
     * @param  r      An ECDSA/secp256k1 signature parameter.
     * @param  s      An ECDSA/secp256k1 signature parameter.
     * @return error  An error, if any, that occurred during the signer recovery.
     * @return signer The address of the account recovered form the signature (0 if error).
     */
    function recoverECDSASigner(
        bytes32 digest,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (Error error, address signer) {
        // Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines
        // the valid range for s in (301): 0 < s < secp256k1n ÷ 2 + 1, and for v in (302): v ∈ {27, 28}.
        if (uint256(s) > uint256(0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0))
            return (Error.InvalidSignatureS, address(0));

        if (v != 27 && v != 28) return (Error.InvalidSignatureV, address(0));

        signer = ecrecover(digest, v, r, s);

        return (signer == address(0)) ? (Error.InvalidSignature, address(0)) : (Error.NoError, signer);
    }

    /**
     * @dev    Returns an error, if any, in validating an ECDSA/secp256k1 signature for a signer and digest.
     * @param  signer    The address of the account purported to have signed.
     * @param  digest    The hash of the data that was signed.
     * @param  signature A byte array ERC1271 signature.
     * @return error     An error, if any, that occurred during the signer recovery.
     */
    function validateECDSASignature(
        address signer,
        bytes32 digest,
        bytes memory signature
    ) internal pure returns (Error error) {
        (Error recoverError, address recoveredSigner) = recoverECDSASigner(digest, signature);

        return (recoverError == Error.NoError) ? validateRecoveredSigner(signer, recoveredSigner) : recoverError;
    }

    /**
     * @dev    Returns an error, if any, in validating an ECDSA/secp256k1 short signature for a signer and digest.
     * @param  signer The address of the account purported to have signed.
     * @param  digest The hash of the data that was signed.
     * @param  r      An ECDSA/secp256k1 signature parameter.
     * @param  vs     An ECDSA/secp256k1 short signature parameter.
     * @return error  An error, if any, that occurred during the signer recovery.
     */
    function validateECDSASignature(
        address signer,
        bytes32 digest,
        bytes32 r,
        bytes32 vs
    ) internal pure returns (Error error) {
        (Error recoverError, address recoveredSigner) = recoverECDSASigner(digest, r, vs);

        return (recoverError == Error.NoError) ? validateRecoveredSigner(signer, recoveredSigner) : recoverError;
    }

    /**
     * @dev    Returns an error, if any, in validating an ECDSA/secp256k1 signature for a signer and digest.
     * @param  signer The address of the account purported to have signed.
     * @param  digest The hash of the data that was signed.
     * @param  v      An ECDSA/secp256k1 signature parameter.
     * @param  r      An ECDSA/secp256k1 signature parameter.
     * @param  s      An ECDSA/secp256k1 signature parameter.
     * @return error  An error, if any, that occurred during the signer recovery.
     */
    function validateECDSASignature(
        address signer,
        bytes32 digest,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (Error error) {
        (Error recoverError, address recoveredSigner) = recoverECDSASigner(digest, v, r, s);

        return (recoverError == Error.NoError) ? validateRecoveredSigner(signer, recoveredSigner) : recoverError;
    }

    /**
     * @dev    Returns an error if `signer` is not `recoveredSigner`.
     * @param  signer          The address of the some signer.
     * @param  recoveredSigner The address of the some recoveredSigner.
     * @return error           An error if `signer` is not `recoveredSigner`.
     */
    function validateRecoveredSigner(address signer, address recoveredSigner) internal pure returns (Error error) {
        return (signer == recoveredSigner) ? Error.NoError : Error.SignerMismatch;
    }
}

/// @title Typed structured data hashing and signing via EIP-712.
/// @dev   An abstract implementation to satisfy EIP-712: https://eips.ethereum.org/EIPS/eip-712
abstract contract ERC712 is IERC712 {
    // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    bytes32 internal constant _EIP712_DOMAIN_HASH = 0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    // keccak256("1")
    bytes32 internal constant _EIP712_VERSION_HASH = 0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6;

    /// @dev Initial Chain ID set at deployment.
    uint256 internal immutable INITIAL_CHAIN_ID;

    /// @dev Initial EIP-712 domain separator set at deployment.
    bytes32 internal immutable INITIAL_DOMAIN_SEPARATOR;

    /// @dev The name of the contract.
    string internal _name;

    /**
     * @notice Constructs the EIP-712 domain separator.
     * @param  name_ The name of the contract.
     */
    constructor(string memory name_) {
        _name = name_;

        INITIAL_CHAIN_ID = block.chainid;
        INITIAL_DOMAIN_SEPARATOR = _getDomainSeparator();
    }

    /******************************************************************************************************************\
    |                                             Public View/Pure Functions                                           |
    \******************************************************************************************************************/

    /// @inheritdoc IERC712
    function DOMAIN_SEPARATOR() public view virtual returns (bytes32) {
        return block.chainid == INITIAL_CHAIN_ID ? INITIAL_DOMAIN_SEPARATOR : _getDomainSeparator();
    }

    /******************************************************************************************************************\
    |                                           Internal View/Pure Functions                                           |
    \******************************************************************************************************************/

    /**
     * @notice Computes the EIP-712 domain separator.
     * @return The EIP-712 domain separator.
     */
    function _getDomainSeparator() internal view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    _EIP712_DOMAIN_HASH,
                    keccak256(bytes(_name)),
                    _EIP712_VERSION_HASH,
                    block.chainid,
                    address(this)
                )
            );
    }

    /**
     * @notice Returns the digest to be signed, via EIP-712, given an internal digest (i.e. hash struct).
     * @param  internalDigest_ The internal digest.
     * @return The digest to be signed.
     */
    function _getDigest(bytes32 internalDigest_) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), internalDigest_));
    }

    /**
     * @notice Returns the signer of a signed digest, via EIP-712, and reverts if the signature is invalid.
     * @param  digest_ The digest that was signed.
     * @param  v_      v of the signature.
     * @param  r_      r of the signature.
     * @param  s_      s of the signature.
     * @return signer_ The signer of the digest.
     */
    function _getSignerAndRevertIfInvalidSignature(
        bytes32 digest_,
        uint8 v_,
        bytes32 r_,
        bytes32 s_
    ) internal pure returns (address signer_) {
        SignatureChecker.Error error_;

        (error_, signer_) = SignatureChecker.recoverECDSASigner(digest_, v_, r_, s_);

        _revertIfError(error_);
    }

    /**
     * @notice Revert if the signature is expired.
     * @param  expiry_ Timestamp at which the signature expires or max uint256 for no expiry.
     */
    function _revertIfExpired(uint256 expiry_) internal view {
        if (expiry_ != type(uint256).max && block.timestamp > expiry_)
            revert SignatureExpired(expiry_, block.timestamp);
    }

    /**
     * @notice Revert if the signature is invalid.
     * @param  signer_    The signer of the signature.
     * @param  digest_    The digest that was signed.
     * @param  signature_ The signature.
     */
    function _revertIfInvalidSignature(address signer_, bytes32 digest_, bytes memory signature_) internal view {
        if (!SignatureChecker.isValidSignature(signer_, digest_, signature_)) revert InvalidSignature();
    }

    /**
     * @notice Revert if the signature is invalid.
     * @param  signer_ The signer of the signature.
     * @param  digest_ The digest that was signed.
     * @param  r_      An ECDSA/secp256k1 signature parameter.
     * @param  vs_     An ECDSA/secp256k1 short signature parameter.
     */
    function _revertIfInvalidSignature(address signer_, bytes32 digest_, bytes32 r_, bytes32 vs_) internal pure {
        _revertIfError(SignatureChecker.validateECDSASignature(signer_, digest_, r_, vs_));
    }

    /**
     * @notice Revert if the signature is invalid.
     * @param  signer_ The signer of the signature.
     * @param  digest_ The digest that was signed.
     * @param  v_      v of the signature.
     * @param  r_      r of the signature.
     * @param  s_      s of the signature.
     */
    function _revertIfInvalidSignature(
        address signer_,
        bytes32 digest_,
        uint8 v_,
        bytes32 r_,
        bytes32 s_
    ) internal pure {
        _revertIfError(SignatureChecker.validateECDSASignature(signer_, digest_, v_, r_, s_));
    }

    /**
     * @notice Revert if error.
     * @param  error_ The SignatureChecker Error enum.
     */
    function _revertIfError(SignatureChecker.Error error_) private pure {
        if (error_ == SignatureChecker.Error.NoError) return;
        if (error_ == SignatureChecker.Error.InvalidSignature) revert InvalidSignature();
        if (error_ == SignatureChecker.Error.InvalidSignatureLength) revert InvalidSignatureLength();
        if (error_ == SignatureChecker.Error.SignerMismatch) revert SignerMismatch();

        revert InvalidSignature();
    }
}

/// @title Stateful Extension for EIP-712 typed structured data hashing and signing with nonces.
/// @dev   An abstract implementation to satisfy stateful EIP-712 with nonces.
abstract contract StatefulERC712 is IStatefulERC712, ERC712 {
    /// @inheritdoc IStatefulERC712
    mapping(address account => uint256 nonce) public nonces; // Nonces for all signatures.

    /**
     * @notice Construct the StatefulERC712 contract.
     * @param  name_ The name of the contract.
     */
    constructor(string memory name_) ERC712(name_) {}
}

/// @title ERC3009 implementation allowing the transfer of fungible assets via a signed authorization.
/// @dev Inherits from ERC712 and StatefulERC712.
abstract contract ERC3009 is IERC3009, StatefulERC712 {
    // keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
    bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH =
        0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267;

    // keccak256("ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
    bytes32 public constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH =
        0xd099cc98ef71107a616c4f0f941f04c322d8e254fe26b3c6668db87aae413de8;

    // keccak256("CancelAuthorization(address authorizer,bytes32 nonce)")
    bytes32 public constant CANCEL_AUTHORIZATION_TYPEHASH =
        0x158b0a9edf7a828aad02f63cd515c68ef2f50ba807396f6d12842833a1597429;

    /// @inheritdoc IERC3009
    mapping(address authorizer => mapping(bytes32 nonce => bool isNonceUsed)) public authorizationState;

    /**
     * @notice Construct the ERC3009 contract.
     * @param  name_     The name of the contract.
     */
    constructor(string memory name_) StatefulERC712(name_) {}

    /******************************************************************************************************************\
    |                                      External/Public Interactive Functions                                       |
    \******************************************************************************************************************/

    /// @inheritdoc IERC3009
    function transferWithAuthorization(
        address from_,
        address to_,
        uint256 value_,
        uint256 validAfter_,
        uint256 validBefore_,
        bytes32 nonce_,
        bytes memory signature_
    ) external {
        _revertIfInvalidSignature(
            from_,
            _getTransferWithAuthorizationDigest(from_, to_, value_, validAfter_, validBefore_, nonce_),
            signature_
        );

        _transferWithAuthorization(from_, to_, value_, validAfter_, validBefore_, nonce_);
    }

    /// @inheritdoc IERC3009
    function transferWithAuthorization(
        address from_,
        address to_,
        uint256 value_,
        uint256 validAfter_,
        uint256 validBefore_,
        bytes32 nonce_,
        bytes32 r_,
        bytes32 vs_
    ) external {
        _revertIfInvalidSignature(
            from_,
            _getTransferWithAuthorizationDigest(from_, to_, value_, validAfter_, validBefore_, nonce_),
            r_,
            vs_
        );

        _transferWithAuthorization(from_, to_, value_, validAfter_, validBefore_, nonce_);
    }

    /// @inheritdoc IERC3009
    function transferWithAuthorization(
        address from_,
        address to_,
        uint256 value_,
        uint256 validAfter_,
        uint256 validBefore_,
        bytes32 nonce_,
        uint8 v_,
        bytes32 r_,
        bytes32 s_
    ) external {
        _revertIfInvalidSignature(
            from_,
            _getTransferWithAuthorizationDigest(from_, to_, value_, validAfter_, validBefore_, nonce_),
            v_,
            r_,
            s_
        );

        _transferWithAuthorization(from_, to_, value_, validAfter_, validBefore_, nonce_);
    }

    /// @inheritdoc IERC3009
    function receiveWithAuthorization(
        address from_,
        address to_,
        uint256 value_,
        uint256 validAfter_,
        uint256 validBefore_,
        bytes32 nonce_,
        bytes memory signature_
    ) external {
        _revertIfInvalidSignature(
            from_,
            _getReceiveWithAuthorizationDigest(from_, to_, value_, validAfter_, validBefore_, nonce_),
            signature_
        );

        _receiveWithAuthorization(from_, to_, value_, validAfter_, validBefore_, nonce_);
    }

    /// @inheritdoc IERC3009
    function receiveWithAuthorization(
        address from_,
        address to_,
        uint256 value_,
        uint256 validAfter_,
        uint256 validBefore_,
        bytes32 nonce_,
        bytes32 r_,
        bytes32 vs_
    ) external {
        _revertIfInvalidSignature(
            from_,
            _getReceiveWithAuthorizationDigest(from_, to_, value_, validAfter_, validBefore_, nonce_),
            r_,
            vs_
        );

        _receiveWithAuthorization(from_, to_, value_, validAfter_, validBefore_, nonce_);
    }

    /// @inheritdoc IERC3009
    function receiveWithAuthorization(
        address from_,
        address to_,
        uint256 value_,
        uint256 validAfter_,
        uint256 validBefore_,
        bytes32 nonce_,
        uint8 v_,
        bytes32 r_,
        bytes32 s_
    ) external {
        _revertIfInvalidSignature(
            from_,
            _getReceiveWithAuthorizationDigest(from_, to_, value_, validAfter_, validBefore_, nonce_),
            v_,
            r_,
            s_
        );

        _receiveWithAuthorization(from_, to_, value_, validAfter_, validBefore_, nonce_);
    }

    /// @inheritdoc IERC3009
    function cancelAuthorization(address authorizer_, bytes32 nonce_, bytes memory signature_) external {
        _revertIfInvalidSignature(authorizer_, _getCancelAuthorizationDigest(authorizer_, nonce_), signature_);
        _cancelAuthorization(authorizer_, nonce_);
    }

    /// @inheritdoc IERC3009
    function cancelAuthorization(address authorizer_, bytes32 nonce_, bytes32 r_, bytes32 vs_) external {
        _revertIfInvalidSignature(authorizer_, _getCancelAuthorizationDigest(authorizer_, nonce_), r_, vs_);
        _cancelAuthorization(authorizer_, nonce_);
    }

    /// @inheritdoc IERC3009
    function cancelAuthorization(address authorizer_, bytes32 nonce_, uint8 v_, bytes32 r_, bytes32 s_) external {
        _revertIfInvalidSignature(authorizer_, _getCancelAuthorizationDigest(authorizer_, nonce_), v_, r_, s_);
        _cancelAuthorization(authorizer_, nonce_);
    }

    /******************************************************************************************************************\
    |                                           Internal View/Pure Functions                                           |
    \******************************************************************************************************************/

    /**
     * @notice Returns the internal EIP-712 digest of a transferWithAuthorization call.
     * @param  from_        Payer's address (Authorizer).
     * @param  to_          Payee's address.
     * @param  value_       Amount to be transferred.
     * @param  validAfter_  The time after which this is valid (unix time).
     * @param  validBefore_ The time before which this is valid (unix time).
     * @param  nonce_       Unique nonce.
     * @return The internal EIP-712 digest.
     */
    function _getTransferWithAuthorizationDigest(
        address from_,
        address to_,
        uint256 value_,
        uint256 validAfter_,
        uint256 validBefore_,
        bytes32 nonce_
    ) internal view returns (bytes32) {
        return
            _getDigest(
                keccak256(
                    abi.encode(
                        TRANSFER_WITH_AUTHORIZATION_TYPEHASH,
                        from_,
                        to_,
                        value_,
                        validAfter_,
                        validBefore_,
                        nonce_
                    )
                )
            );
    }

    /**
     * @notice Common transfer function used by `transferWithAuthorization` and `_receiveWithAuthorization`.
     * @param  from_        Payer's address (Authorizer).
     * @param  to_          Payee's address.
     * @param  value_       Amount to be transferred.
     * @param  validAfter_  The time after which this is valid (unix time).
     * @param  validBefore_ The time before which this is valid (unix time).
     * @param  nonce_       Unique nonce.
     */
    function _transferWithAuthorization(
        address from_,
        address to_,
        uint256 value_,
        uint256 validAfter_,
        uint256 validBefore_,
        bytes32 nonce_
    ) internal {
        if (block.timestamp < validAfter_) revert AuthorizationNotYetValid(block.timestamp, validAfter_);
        if (block.timestamp > validBefore_) revert AuthorizationExpired(block.timestamp, validBefore_);

        _revertIfAuthorizationAlreadyUsed(from_, nonce_);

        authorizationState[from_][nonce_] = true;

        emit AuthorizationUsed(from_, nonce_);

        _transfer(from_, to_, value_);
    }

    /**
     * @notice Returns the internal EIP-712 digest of a receiveWithAuthorization call.
     * @param  from_        Payer's address (Authorizer).
     * @param  to_          Payee's address.
     * @param  value_       Amount to be transferred.
     * @param  validAfter_  The time after which this is valid (unix time).
     * @param  validBefore_ The time before which this is valid (unix time).
     * @param  nonce_       Unique nonce.
     * @return The internal EIP-712 digest.
     */
    function _getReceiveWithAuthorizationDigest(
        address from_,
        address to_,
        uint256 value_,
        uint256 validAfter_,
        uint256 validBefore_,
        bytes32 nonce_
    ) internal view returns (bytes32) {
        return
            _getDigest(
                keccak256(
                    abi.encode(
                        RECEIVE_WITH_AUTHORIZATION_TYPEHASH,
                        from_,
                        to_,
                        value_,
                        validAfter_,
                        validBefore_,
                        nonce_
                    )
                )
            );
    }

    /**
     * @notice Common receive function used by `receiveWithAuthorization`.
     * @param  from_        Payer's address (Authorizer).
     * @param  to_          Payee's address.
     * @param  value_       Amount to be transferred.
     * @param  validAfter_  The time after which this is valid (unix time).
     * @param  validBefore_ The time before which this is valid (unix time).
     * @param  nonce_       Unique nonce.
     */
    function _receiveWithAuthorization(
        address from_,
        address to_,
        uint256 value_,
        uint256 validAfter_,
        uint256 validBefore_,
        bytes32 nonce_
    ) internal {
        if (msg.sender != to_) revert CallerMustBePayee(msg.sender, to_);

        _transferWithAuthorization(from_, to_, value_, validAfter_, validBefore_, nonce_);
    }

    /**
     * @notice Returns the internal EIP-712 digest of a cancelAuthorization call.
     * @param  authorizer_ Authorizer's address.
     * @param  nonce_      Nonce of the authorization.
     * @return The internal EIP-712 digest.
     */
    function _getCancelAuthorizationDigest(address authorizer_, bytes32 nonce_) internal view returns (bytes32) {
        return _getDigest(keccak256(abi.encode(CANCEL_AUTHORIZATION_TYPEHASH, authorizer_, nonce_)));
    }

    /**
     * @notice Common cancel function used by `cancelAuthorization`.
     * @param  authorizer_ Authorizer's address.
     * @param  nonce_      Nonce of the authorization.
     */
    function _cancelAuthorization(address authorizer_, bytes32 nonce_) internal {
        if (authorizationState[authorizer_][nonce_]) revert AuthorizationAlreadyUsed(authorizer_, nonce_);

        authorizationState[authorizer_][nonce_] = true;

        emit AuthorizationCanceled(authorizer_, nonce_);
    }

    /**
     * @notice Reverts if the authorization is already used.
     * @param  authorizer_ The authorizer's address.
     * @param  nonce_      The nonce of the authorization.
     */
    function _revertIfAuthorizationAlreadyUsed(address authorizer_, bytes32 nonce_) internal view {
        if (authorizationState[authorizer_][nonce_]) revert AuthorizationAlreadyUsed(authorizer_, nonce_);
    }

    /**
     * @notice ERC20 transfer function that needs to be overridden by the inheriting contract.
     * @param  sender_    The sender's address.
     * @param  recipient_ The recipient's address.
     * @param  amount_    The amount to be transferred.
     */
    function _transfer(address sender_, address recipient_, uint256 amount_) internal virtual;
}

/// @title An ERC20 token extended with EIP-2612 permits for signed approvals (via EIP-712 and with EIP-1271
///        compatibility), and extended with EIP-3009 transfer with authorization (via EIP-712).
abstract contract ERC20Extended is IERC20Extended, ERC3009 {
    /**
     * @inheritdoc IERC20Extended
     * @dev Keeping this constant, despite `permit` parameter name differences, to ensure max EIP-2612 compatibility.
     *      keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)")
     */
    bytes32 public constant PERMIT_TYPEHASH = 0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;

    uint8 public immutable decimals;

    /// @inheritdoc IERC20
    string public symbol;

    /// @inheritdoc IERC20
    mapping(address account => mapping(address spender => uint256 allowance)) public allowance;

    /**
     * @notice Constructs the ERC20Extended contract.
     * @param  name_     The name of the token.
     * @param  symbol_   The symbol of the token.
     * @param  decimals_ The number of decimals the token uses.
     */
    constructor(string memory name_, string memory symbol_, uint8 decimals_) ERC3009(name_) {
        symbol = symbol_;
        decimals = decimals_;
    }

    /******************************************************************************************************************\
    |                                      External/Public Interactive Functions                                       |
    \******************************************************************************************************************/

    /// @inheritdoc IERC20
    function approve(address spender_, uint256 amount_) external returns (bool success_) {
        _approve(msg.sender, spender_, amount_);
        return true;
    }

    /// @inheritdoc IERC20Extended
    function permit(
        address owner_,
        address spender_,
        uint256 value_,
        uint256 deadline_,
        uint8 v_,
        bytes32 r_,
        bytes32 s_
    ) external {
        // NOTE: `_permit` returns the digest.
        _revertIfInvalidSignature(owner_, _permit(owner_, spender_, value_, deadline_), v_, r_, s_);
    }

    /// @inheritdoc IERC20Extended
    function permit(
        address owner_,
        address spender_,
        uint256 value_,
        uint256 deadline_,
        bytes memory signature_
    ) external {
        // NOTE: `_permit` returns the digest.
        _revertIfInvalidSignature(owner_, _permit(owner_, spender_, value_, deadline_), signature_);
    }

    /// @inheritdoc IERC20
    function transfer(address recipient_, uint256 amount_) external returns (bool success_) {
        _transfer(msg.sender, recipient_, amount_);
        return true;
    }

    /// @inheritdoc IERC20
    function transferFrom(address sender_, address recipient_, uint256 amount_) external returns (bool success_) {
        uint256 spenderAllowance_ = allowance[sender_][msg.sender]; // Cache `spenderAllowance_` to stack.

        if (spenderAllowance_ != type(uint256).max) {
            _approve(sender_, msg.sender, spenderAllowance_ - amount_);
        }

        _transfer(sender_, recipient_, amount_);

        return true;
    }

    /******************************************************************************************************************\
    |                                       External/Public View/Pure Functions                                        |
    \******************************************************************************************************************/

    /// @inheritdoc IERC20
    function name() external view returns (string memory name_) {
        return _name;
    }

    /******************************************************************************************************************\
    |                                          Internal Interactive Functions                                          |
    \******************************************************************************************************************/

    function _approve(address account_, address spender_, uint256 amount_) internal virtual {
        emit Approval(account_, spender_, allowance[account_][spender_] = amount_);
    }

    function _permit(
        address owner_,
        address spender_,
        uint256 amount_,
        uint256 deadline_
    ) internal virtual returns (bytes32 digest_) {
        _revertIfExpired(deadline_);

        uint256 nonce_ = nonces[owner_]; // Cache `nonce_` to stack.

        unchecked {
            nonces[owner_] = nonce_ + 1; // Nonce realistically cannot overflow.
        }

        _approve(owner_, spender_, amount_);

        return _getDigest(keccak256(abi.encode(PERMIT_TYPEHASH, owner_, spender_, amount_, nonce_, deadline_)));
    }
}

abstract contract ERC5805 is IERC5805, StatefulERC712 {
    // NOTE: Keeping this constant, despite `delegateBySig` parameter name differences, to ensure max EIP-5805 compatibility.
    // keccak256("Delegation(address delegatee,uint256 nonce,uint256 expiry)")
    bytes32 public constant DELEGATION_TYPEHASH = 0xe48329057bfd03d55e49b547132e39cffd9c1820ad7b9d4c5307691425d15adf;

    /******************************************************************************************************************\
    |                                      External/Public Interactive Functions                                       |
    \******************************************************************************************************************/

    /// @inheritdoc IERC5805
    function delegate(address delegatee_) external {
        _delegate(msg.sender, delegatee_);
    }

    /// @inheritdoc IERC5805
    function delegateBySig(
        address delegatee_,
        uint256 nonce_,
        uint256 expiry_,
        uint8 v_,
        bytes32 r_,
        bytes32 s_
    ) external {
        bytes32 digest_ = _getDelegationDigest(delegatee_, nonce_, expiry_);
        address signer_ = _getSignerAndRevertIfInvalidSignature(digest_, v_, r_, s_);

        _revertIfExpired(expiry_);
        _checkAndIncrementNonce(signer_, nonce_);
        _delegate(signer_, delegatee_);
    }

    /******************************************************************************************************************\
    |                                          Internal Interactive Functions                                          |
    \******************************************************************************************************************/

    /**
     * @dev   Reverts if a given nonce is reused for `account_`, then increments the nonce in storage.
     * @param account_ The address of the account the nonce is being verifier for.
     * @param nonce_   The nonce being used by the account.
     */
    function _checkAndIncrementNonce(address account_, uint256 nonce_) internal {
        uint256 currentNonce_ = nonces[account_];

        if (nonce_ != currentNonce_) revert ReusedNonce(nonce_, currentNonce_);

        unchecked {
            nonces[account_] = currentNonce_ + 1; // Nonce realistically cannot overflow.
        }
    }

    /**
     * @dev   Delegate voting power from `delegator_` to `newDelegatee_`.
     * @param delegator_    The address of the account delegating voting power.
     * @param newDelegatee_ The address of the account receiving voting power.
     */
    function _delegate(address delegator_, address newDelegatee_) internal virtual;

    /******************************************************************************************************************\
    |                                           Internal View/Pure Functions                                           |
    \******************************************************************************************************************/

    /**
     * @dev    Returns the digest to be signed, via EIP-712, given an internal digest (i.e. hash struct).
     * @param  delegatee_ The address of the delegatee to delegate to.
     * @param  nonce_     The nonce of the account delegating.
     * @param  expiry_    The last timestamp at which the signature is still valid.
     * @return The digest to be signed.
     */
    function _getDelegationDigest(address delegatee_, uint256 nonce_, uint256 expiry_) internal view returns (bytes32) {
        return _getDigest(keccak256(abi.encode(DELEGATION_TYPEHASH, delegatee_, nonce_, expiry_)));
    }
}

/// @title Extension for an ERC5805 token that uses epochs as its clock mode and delegation via IERC1271.
abstract contract EpochBasedVoteToken is IEpochBasedVoteToken, ERC5805, ERC20Extended {
    /// @dev A 32-byte struct containing a starting epoch and an address that is valid until the next AccountSnap.
    struct AccountSnap {
        uint16 startingEpoch;
        address account;
    }

    /// @dev A 32-byte struct containing a starting epoch and an amount that is valid until the next AmountSnap.
    struct AmountSnap {
        uint16 startingEpoch;
        uint240 amount;
    }

    /// @dev Store the total supply per epoch.
    AmountSnap[] internal _totalSupplies;

    /// @dev Store the balance per epoch per account.
    mapping(address account => AmountSnap[] balanceSnaps) internal _balances;

    /// @dev Store the delegatee per epoch per account.
    mapping(address account => AccountSnap[] delegateeSnaps) internal _delegatees;

    /// @dev Store the voting power per epoch per delegatee.
    mapping(address delegatee => AmountSnap[] votingPowerSnaps) internal _votingPowers;

    /**
     * @notice Constructs a new EpochBasedVoteToken contract.
     * @param  name_     The name of the token.
     * @param  symbol_   The symbol of the token.
     * @param  decimals_ The decimals of the token.
     */
    constructor(string memory name_, string memory symbol_, uint8 decimals_) ERC20Extended(name_, symbol_, decimals_) {}

    /******************************************************************************************************************\
    |                                      External/Public Interactive Functions                                       |
    \******************************************************************************************************************/

    /// @inheritdoc IEpochBasedVoteToken
    function delegateBySig(
        address account_,
        address delegatee_,
        uint256 nonce_,
        uint256 expiry_,
        bytes memory signature_
    ) external {
        _revertIfExpired(expiry_);
        _revertIfInvalidSignature(account_, _getDelegationDigest(delegatee_, nonce_, expiry_), signature_);
        _checkAndIncrementNonce(account_, nonce_);
        _delegate(account_, delegatee_);
    }

    /******************************************************************************************************************\
    |                                       External/Public View/Pure Functions                                        |
    \******************************************************************************************************************/

    /// @inheritdoc IERC20
    function balanceOf(address account_) external view returns (uint256) {
        return _getBalance(account_, _clock());
    }

    /// @inheritdoc IEpochBasedVoteToken
    function getDelegationDigest(address delegatee_, uint256 nonce_, uint256 expiry_) external view returns (bytes32) {
        return _getDelegationDigest(delegatee_, nonce_, expiry_);
    }

    /// @inheritdoc IEpochBasedVoteToken
    function pastBalanceOf(address account_, uint256 epoch_) external view returns (uint256) {
        uint16 safeEpoch_ = UIntMath.safe16(epoch_);

        _revertIfNotPastTimepoint(safeEpoch_); // Per EIP-5805, should revert if `epoch_` is not in the past.

        return _getBalance(account_, safeEpoch_);
    }

    /// @inheritdoc IERC6372
    function clock() external view returns (uint48 clock_) {
        return _clock();
    }

    /// @inheritdoc IERC5805
    function delegates(address account_) external view returns (address) {
        return _getDelegatee(account_, _clock());
    }

    /// @inheritdoc IEpochBasedVoteToken
    function pastDelegates(address account_, uint256 epoch_) external view returns (address) {
        uint16 safeEpoch_ = UIntMath.safe16(epoch_);

        _revertIfNotPastTimepoint(safeEpoch_); // Per EIP-5805, should revert if `epoch_` is not in the past.

        return _getDelegatee(account_, safeEpoch_);
    }

    /// @inheritdoc IERC5805
    function getVotes(address account_) external view returns (uint256) {
        return _getVotes(account_, _clock());
    }

    /// @inheritdoc IERC5805
    function getPastVotes(address account_, uint256 epoch_) external view returns (uint256) {
        uint16 safeEpoch_ = UIntMath.safe16(epoch_);

        _revertIfNotPastTimepoint(safeEpoch_); // Per EIP-5805, should revert if `epoch_` is not in the past.

        return _getVotes(account_, safeEpoch_);
    }

    /// @inheritdoc IERC20
    function totalSupply() external view override returns (uint256) {
        return _getTotalSupply(_clock());
    }

    /// @inheritdoc IEpochBasedVoteToken
    function pastTotalSupply(uint256 epoch_) external view returns (uint256) {
        uint16 safeEpoch_ = UIntMath.safe16(epoch_);

        _revertIfNotPastTimepoint(safeEpoch_); // Per EIP-5805, should revert if `epoch_` is not in the past.

        return _getTotalSupply(safeEpoch_);
    }

    /// @inheritdoc IERC6372
    function CLOCK_MODE() external pure returns (string memory clockMode_) {
        return "mode=epoch";
    }

    /******************************************************************************************************************\
    |                                          Internal Interactive Functions                                          |
    \******************************************************************************************************************/

    /**
     * @dev   Add `amount_` to the balance of `account_`, using unchecked math.
     * @param account_ The address of the account to add the balance to.
     * @param amount_  The amount to add to the balance.
     */
    function _addBalance(address account_, uint240 amount_) internal {
        _updateBalance(account_, _addUnchecked, amount_); // Update balance using `_addUnchecked` operation.
    }

    /**
     * @dev   Add `amount_` to the total supply, using checked math.
     * @param amount_ The amount to add to the total supply.
     */
    function _addTotalSupply(uint240 amount_) internal {
        _update(_totalSupplies, _add, amount_); // Update total supply using `_add` operation.
    }

    /**
     * @dev   Add `amount_` to the voting power of `account_`, using unchecked math.
     * @param account_ The address of the account to add the voting power to.
     * @param amount_  The amount to add to the voting power.
     */
    function _addVotingPower(address account_, uint240 amount_) internal {
        _updateVotingPower(account_, _addUnchecked, amount_); // Update voting power using `_addUnchecked` operation.
    }

    /**
     * @dev   Set a new delegatee for `delegator_`.
     * @param delegator_    The address of the account delegating voting power.
     * @param newDelegatee_ The address of the account receiving voting power.
     */
    function _delegate(address delegator_, address newDelegatee_) internal virtual override {
        address oldDelegatee_ = _setDelegatee(delegator_, newDelegatee_);
        uint240 votingPower_ = _getBalance(delegator_, _clock());

        if (votingPower_ == 0) return;

        _removeVotingPower(oldDelegatee_, votingPower_);
        _addVotingPower(newDelegatee_, votingPower_);
    }

    /**
     * @dev   Mint `amount_` tokens to `recipient_`.
     * @param recipient_ The address of the account to mint tokens to.
     * @param amount_    The amount of tokens to mint.
     */
    function _mint(address recipient_, uint256 amount_) internal virtual {
        emit Transfer(address(0), recipient_, amount_);

        uint240 safeAmount_ = UIntMath.safe240(amount_);

        _addTotalSupply(safeAmount_); // Will revert on overflow.
        _addBalance(recipient_, safeAmount_);
        _addVotingPower(_getDelegatee(recipient_, _clock()), safeAmount_);
    }

    /**
     * @dev   Subtract `amount_` from the balance of `account_`, using checked math.
     * @param account_ The address of the account to subtract the balance from.
     * @param amount_  The amount to subtract from the balance.
     */
    function _removeBalance(address account_, uint240 amount_) internal {
        _updateBalance(account_, _sub, amount_); // Update balance using `_sub` operation.
    }

    /**
     * @dev   Subtract `amount_` of voting power from the balance of `account_`, using checked math.
     * @param account_ The address of the account to subtract the voting power from.
     * @param amount_  The amount of voting power to subtract.
     */
    function _removeVotingPower(address account_, uint240 amount_) internal {
        _updateVotingPower(account_, _sub, amount_); // Update voting power using `_sub` operation.
    }

    /**
     * @dev    Set a new delegatee for `delegator_`.
     * @param  delegator_    The address of the account delegating voting power.
     * @param  delegatee_    The address of the account receiving voting power.
     * @return oldDelegatee_ The address of the previous delegatee of `delegator_`.
     */
    function _setDelegatee(address delegator_, address delegatee_) internal returns (address oldDelegatee_) {
        // `delegatee_` will be `delegator_` (the default) if `delegatee_` was passed in as `address(0)`.
        delegatee_ = _getDefaultIfZero(delegatee_, delegator_);

        // The delegatee to write to storage will be `address(0)` if `delegatee_` is `delegator_` (the default).
        address delegateeToWrite_ = _getZeroIfDefault(delegatee_, delegator_);
        uint16 currentEpoch_ = _clock();
        AccountSnap[] storage delegateeSnaps_ = _delegatees[delegator_];
        uint256 length_ = delegateeSnaps_.length;

        // If this will be the first AccountSnap, we can just push it onto the empty array.
        if (length_ == 0) {
            delegateeSnaps_.push(AccountSnap(currentEpoch_, delegateeToWrite_));

            return delegator_; // In this case, delegatee has always been the `delegator_` itself.
        }

        unchecked {
            --length_;
        }

        AccountSnap storage latestDelegateeSnap_ = _unsafeAccess(delegateeSnaps_, length_);

        // `oldDelegatee_` will be `delegator_` (the default) if it was retrieved as `address(0)`.
        oldDelegatee_ = _getDefaultIfZero(latestDelegateeSnap_.account, delegator_);

        emit DelegateChanged(delegator_, oldDelegatee_, delegatee_);

        // If the current epoch is greater than the last AccountSnap's startingEpoch, we can push a new
        // AccountSnap onto the array, else we can just update the last AccountSnap's account.
        if (currentEpoch_ > latestDelegateeSnap_.startingEpoch) {
            delegateeSnaps_.push(AccountSnap(currentEpoch_, delegateeToWrite_));
        } else {
            latestDelegateeSnap_.account = delegateeToWrite_;
        }
    }

    /**
     * @dev   Transfer `amount_` tokens from `sender_` to `recipient_`.
     * @param sender_    The address of the account to transfer tokens from.
     * @param recipient_ The address of the account to transfer tokens to.
     * @param amount_    The amount of tokens to transfer.
     */
    function _transfer(address sender_, address recipient_, uint256 amount_) internal virtual override {
        emit Transfer(sender_, recipient_, amount_);

        uint240 safeAmount_ = UIntMath.safe240(amount_);
        uint16 currentEpoch_ = _clock();

        _removeBalance(sender_, safeAmount_); // Will revert on underflow.
        _removeVotingPower(_getDelegatee(sender_, currentEpoch_), safeAmount_); // Will revert on underflow.
        _addBalance(recipient_, safeAmount_);
        _addVotingPower(_getDelegatee(recipient_, currentEpoch_), safeAmount_);
    }

    /**
     * @dev    Update a storage AmountSnap array of given by `amount_` given `operation_`.
     * @param  amountSnaps_ The storage pointer to an AmountSnap array to update.
     * @param  operation_   The operation to perform on the old and new amounts.
     * @param  amount_      The amount to update the Snap by.
     * @return oldAmount_   The previous latest amount of the Snap array.
     * @return newAmount_   The new latest amount of the Snap array.
     */
    function _update(
        AmountSnap[] storage amountSnaps_,
        function(uint240, uint240) returns (uint240) operation_,
        uint240 amount_
    ) internal returns (uint240 oldAmount_, uint240 newAmount_) {
        uint16 currentEpoch_ = _clock();
        uint256 length_ = amountSnaps_.length;

        // If this will be the first AmountSnap, we can just push it onto the empty array.
        if (length_ == 0) {
            // NOTE: `operation_(0, amount_)` is necessary for almost all operations other than setting or adding.
            amountSnaps_.push(AmountSnap(currentEpoch_, operation_(0, amount_)));

            return (0, amount_); // In this case, the old amount was 0.
        }

        unchecked {
            --length_;
        }

        AmountSnap storage lastAmountSnap_ = _unsafeAccess(amountSnaps_, length_);
        newAmount_ = operation_(oldAmount_ = lastAmountSnap_.amount, amount_);

        // If the current epoch is greater than the last AmountSnap's startingEpoch, we can push a new
        // AmountSnap onto the array, else we can just update the last AmountSnap's amount.
        if (currentEpoch_ > lastAmountSnap_.startingEpoch) {
            amountSnaps_.push(AmountSnap(currentEpoch_, newAmount_));
        } else {
            lastAmountSnap_.amount = newAmount_;
        }
    }

    /**
     * @dev   Update the balance of `account_` by `amount_` given `operation_`.
     * @param account_   The address of the account to update the balance of.
     * @param operation_ The operation to perform on the old and new amounts.
     * @param amount_    The amount to update the balance by.
     */
    function _updateBalance(
        address account_,
        function(uint240, uint240) returns (uint240) operation_,
        uint240 amount_
    ) internal {
        _update(_balances[account_], operation_, amount_);
    }

    /**
     * @dev   Update the voting power of `delegatee_` by `amount_` given `operation_`.
     * @param delegatee_ The address of the account to update the voting power of.
     * @param operation_ The operation to perform on the old and new amounts.
     * @param amount_    The amount to update the voting power by.
     */
    function _updateVotingPower(
        address delegatee_,
        function(uint240, uint240) returns (uint240) operation_,
        uint240 amount_
    ) internal {
        (uint240 oldAmount_, uint240 newAmount_) = _update(_votingPowers[delegatee_], operation_, amount_);

        emit DelegateVotesChanged(delegatee_, oldAmount_, newAmount_);
    }

    /******************************************************************************************************************\
    |                                           Internal View/Pure Functions                                           |
    \******************************************************************************************************************/

    /**
     * @notice Returns the current timepoint according to the mode the contract is operating on.
     * @return Current timepoint.
     */
    function _clock() internal view returns (uint16) {
        return PureEpochs.currentEpoch();
    }

    /**
     * @dev    Get the balance of `account_` at `epoch_`.
     * @param  account_ The address of the account to get the balance of.
     * @param  epoch_   The epoch to get the balance at.
     * @return The balance of `account_` at `epoch_`.
     */
    function _getBalance(address account_, uint16 epoch_) internal view virtual returns (uint240) {
        return _getValueAt(_balances[account_], epoch_);
    }

    /**
     * @dev    Get the delegatee of `account_` at `epoch_`.
     * @dev    The delegatee is the account itself (the default) if the retrieved delegatee is address(0).
     * @param  account_ The address of the account to get the delegatee of.
     * @param  epoch_   The epoch to get the delegatee at.
     * @return The delegatee of `account_` at `epoch_`.
     */
    function _getDelegatee(address account_, uint256 epoch_) internal view virtual returns (address) {
        AccountSnap[] storage delegateeSnaps_ = _delegatees[account_];

        uint256 index_ = delegateeSnaps_.length; // NOTE: `index_` starts out as length, and would be out of bounds.

        // Keep going back until we find the first snap with a startingEpoch less than or equal to `epoch_`. This snap
        // has the account applicable to `epoch_`. If we exhaust the array, then the delegatee is address(0).
        while (index_ > 0) {
            AccountSnap storage accountSnap_ = _unsafeAccess(delegateeSnaps_, --index_);

            if (accountSnap_.startingEpoch <= epoch_) return _getDefaultIfZero(accountSnap_.account, account_);
        }

        return account_;
    }

    /**
     * @dev    Get the total supply at `epoch_`.
     * @param  epoch_ The epoch to get the total supply at.
     * @return The total supply at `epoch_`.
     */
    function _getTotalSupply(uint16 epoch_) internal view virtual returns (uint240) {
        return _getValueAt(_totalSupplies, epoch_);
    }

    /**
     * @dev    Get the value of an AmountSnap array at a given epoch.
     * @param  amountSnaps_ The array of AmountSnaps to get the value of.
     * @param  epoch_       The epoch to get the value at.
     * @return The value of the AmountSnap array at `epoch_`.
     */
    function _getValueAt(AmountSnap[] storage amountSnaps_, uint16 epoch_) internal view returns (uint240) {
        uint256 index_ = amountSnaps_.length; // NOTE: `index_` starts out as length, and would be out of bounds.

        // Keep going back until we find the first snap with a startingEpoch less than or equal to `epoch_`. This snap
        // has the amount applicable to `epoch_`. If we exhaust the array, then the amount is 0.
        while (index_ > 0) {
            AmountSnap storage amountSnap_ = _unsafeAccess(amountSnaps_, --index_);

            if (amountSnap_.startingEpoch <= epoch_) return amountSnap_.amount;
        }

        return 0;
    }

    /**
     * @dev    The votes of `account_` at `epoch_`.
     * @param  account_ The address of the account to get the votes of.
     * @param  epoch_   The epoch to get the votes at.
     * @return The votes of `account_` at `epoch_`.
     */
    function _getVotes(address account_, uint16 epoch_) internal view virtual returns (uint240) {
        return _getValueAt(_votingPowers[account_], epoch_);
    }

    /**
     * @dev   Revert if `epoch_` is not in the past.
     * @param epoch_ The epoch to check.
     */
    function _revertIfNotPastTimepoint(uint16 epoch_) internal view {
        uint16 currentEpoch_ = _clock();

        if (epoch_ >= currentEpoch_) revert NotPastTimepoint(epoch_, currentEpoch_);
    }

    /**
     * @dev    Add `b_` to `a_`, using checked math.
     * @param  a_ The amount to add to.
     * @param  b_ The amount to add.
     * @return The sum of `a_` and `b_`.
     */
    function _add(uint240 a_, uint240 b_) internal pure returns (uint240) {
        return a_ + b_;
    }

    /**
     * @dev    Add `b_` to `a_`, using unchecked math.
     * @param  a_ The amount to add to.
     * @param  b_ The amount to add.
     * @return The sum of `a_` and `b_`.
     */
    function _addUnchecked(uint240 a_, uint240 b_) internal pure returns (uint240) {
        unchecked {
            return a_ + b_;
        }
    }

    /**
     * @dev    Return `default_` if `input_` is equal to address(0), else return `input_`.
     * @param  input_   The input address.
     * @param  default_ The default address.
     * @return The input address if not equal to the zero address, else the default address.
     */
    function _getDefaultIfZero(address input_, address default_) internal pure returns (address) {
        return input_ == address(0) ? default_ : input_;
    }

    /**
     * @dev Return address(0) if `input_` is `default_`, else return `input_`.
     * @param  input_   The input address.
     * @param  default_ The default address.
     * @return The input address if it is not the default address, else address(0).
     */
    function _getZeroIfDefault(address input_, address default_) internal pure returns (address) {
        return input_ == default_ ? address(0) : input_;
    }

    /**
     * @dev    Subtract `b_` from `a_`, using checked math.
     * @param  a_ The amount to subtract from.
     * @param  b_ The amount to subtract.
     * @return The difference of `a_` and `b_`.
     */
    function _sub(uint240 a_, uint240 b_) internal pure returns (uint240) {
        return a_ - b_;
    }

    /**
     * @dev    Subtract `b_` from `a_`, using unchecked math.
     * @param  a_ The amount to subtract from.
     * @param  b_ The amount to subtract.
     * @return The difference of `a_` and `b_`.
     */
    function _subUnchecked(uint240 a_, uint240 b_) internal pure returns (uint240) {
        unchecked {
            return a_ - b_;
        }
    }

    /**
     * @dev    Returns the AmountSnap in an array at a given index without doing bounds checking.
     * @param  amountSnaps_ The array of AmountSnaps to parse.
     * @param  index_       The index of the AmountSnap to return.
     * @return amountSnap_  The AmountSnap at `index_`.
     */
    function _unsafeAccess(
        AmountSnap[] storage amountSnaps_,
        uint256 index_
    ) internal pure returns (AmountSnap storage amountSnap_) {
        assembly {
            mstore(0, amountSnaps_.slot)
            amountSnap_.slot := add(keccak256(0, 0x20), index_)
        }
    }

    /**
     * @dev    Returns the AccountSnap in an array at a given index without doing bounds checking.
     * @param  accountSnaps_ The array of AccountSnaps to parse.
     * @param  index_        The index of the AccountSnap to return.
     * @return accountSnap_  The AccountSnap at `index_`.
     */
    function _unsafeAccess(
        AccountSnap[] storage accountSnaps_,
        uint256 index_
    ) internal pure returns (AccountSnap storage accountSnap_) {
        assembly {
            mstore(0, accountSnaps_.slot)
            accountSnap_.slot := add(keccak256(0, 0x20), index_)
        }
    }
}

// NOTE: There is no feasible way to emit `Transfer` events for inflationary minting such that external client can
//       index them and track balances and total supply correctly. Specifically,a nd only for total supply indexing, one
//       can assume that total supply is the sum of all voting powers, thus tracking the deltas of the
//       `DelegateVotesChanged` events will suffice.

/// @title Extension for an EpochBasedVoteToken token that allows for inflating tokens and voting power.
abstract contract EpochBasedInflationaryVoteToken is IEpochBasedInflationaryVoteToken, EpochBasedVoteToken {
    /// @dev A 32-byte struct containing a starting epoch that merely marks that something occurred in this epoch.
    struct VoidSnap {
        uint16 startingEpoch;
    }

    /// @inheritdoc IEpochBasedInflationaryVoteToken
    uint16 public constant ONE = 10_000; // 100% in basis points.

    /// @inheritdoc IEpochBasedInflationaryVoteToken
    uint16 public immutable participationInflation; // In basis points.

    mapping(address delegatee => VoidSnap[] participationSnaps) internal _participations;

    mapping(address account => VoidSnap[] lastSyncSnaps) internal _lastSyncs;

    modifier notDuringVoteEpoch() {
        _revertIfInVoteEpoch();
        _;
    }

    modifier onlyDuringVoteEpoch() {
        _revertIfNotInVoteEpoch();
        _;
    }

    /**
     * @notice Constructs a new EpochBasedInflationaryVoteToken contract.
     * @param  name_                   The name of the token.
     * @param  symbol_                 The symbol of the token.
     * @param  decimals_               The decimals of the token.
     * @param  participationInflation_ The participation inflation rate used to inflate tokens for participation.
     */
    constructor(
        string memory name_,
        string memory symbol_,
        uint8 decimals_,
        uint16 participationInflation_
    ) EpochBasedVoteToken(name_, symbol_, decimals_) {
        if (participationInflation_ > ONE) revert InflationTooHigh();

        participationInflation = participationInflation_;
    }

    /******************************************************************************************************************\
    |                                       External/Public View/Pure Functions                                        |
    \******************************************************************************************************************/

    /// @inheritdoc IEpochBasedInflationaryVoteToken
    function hasParticipatedAt(address delegatee_, uint256 epoch_) external view returns (bool) {
        return _hasParticipatedAt(delegatee_, UIntMath.safe16(epoch_));
    }

    /******************************************************************************************************************\
    |                                          Internal Interactive Functions                                          |
    \******************************************************************************************************************/

    /**
     * @dev   Delegate voting power from `delegator_` to `newDelegatee_`.
     * @param delegator_    The address of the account delegating voting power.
     * @param newDelegatee_ The address of the account receiving voting power.
     */
    function _delegate(address delegator_, address newDelegatee_) internal virtual override notDuringVoteEpoch {
        _sync(delegator_);
        super._delegate(delegator_, newDelegatee_);
    }

    /**
     * @dev   Allows for the inflation of a delegatee's voting power (and total supply) up to one time per epoch.
     * @param delegatee_ The address of the account being marked as having participated.
     */
    function _markParticipation(address delegatee_) internal virtual onlyDuringVoteEpoch {
        if (!_update(_participations[delegatee_])) revert AlreadyParticipated(); // Revert if could not update.

        _sync(delegatee_);

        uint240 inflation_ = _getInflation(_getVotes(delegatee_, _clock()));

        // NOTE: Cannot sync here because it would prevent `delegatee_` from getting inflation if their delegatee votes.
        // NOTE: Don't need to sync here because participating has no effect on the balance of `delegatee_`.
        _addTotalSupply(inflation_);
        _addVotingPower(delegatee_, inflation_);
    }

    /**
     * @dev   Mint `amount_` tokens to `recipient_`.
     * @param recipient_ The address of the account to mint tokens to.
     * @param amount_    The amount of tokens to mint.
     */
    function _mint(address recipient_, uint256 amount_) internal virtual override notDuringVoteEpoch {
        _sync(recipient_);
        super._mint(recipient_, amount_);
    }

    /**
     * @dev   Syncs `account_` so that it balance Snap array in storage, reflects their unrealized inflation.
     * @param account_ The address of the account to sync.
     */
    function _sync(address account_) internal {
        // Realized the account's unrealized inflation since the its last sync, and update its last sync.
        _addBalance(account_, _getUnrealizedInflation(account_, _clock()));
        _update(_lastSyncs[account_]);
    }

    /**
     * @dev Transfers `amount_` tokens from `sender_` to `recipient_`.
     * @param sender_    The address of the account to transfer tokens from.
     * @param recipient_ The address of the account to transfer tokens to.
     * @param amount_    The amount of tokens to transfer.
     */
    function _transfer(
        address sender_,
        address recipient_,
        uint256 amount_
    ) internal virtual override notDuringVoteEpoch {
        _sync(sender_);
        _sync(recipient_);
        super._transfer(sender_, recipient_, amount_);
    }

    /**
     * @dev    Update a storage VoidSnap array to contain the current epoch as the latest snap.
     * @param  voidSnaps_ The storage pointer to a VoidSnap array to update.
     * @return updated_   Whether the VoidSnap array was updated, and thus did not already contain the current epoch.
     */
    function _update(VoidSnap[] storage voidSnaps_) internal returns (bool updated_) {
        uint16 currentEpoch_ = _clock();
        uint256 length_ = voidSnaps_.length;

        unchecked {
            // If this will be the first or a new VoidSnap, just push it onto the array.
            if (updated_ = ((length_ == 0) || (currentEpoch_ > _unsafeAccess(voidSnaps_, length_ - 1).startingEpoch))) {
                voidSnaps_.push(VoidSnap(currentEpoch_));
            }
        }
    }

    /******************************************************************************************************************\
    |                                           Internal View/Pure Functions                                           |
    \******************************************************************************************************************/

    /**
     * @dev    Returns the balance of `account_` plus any inflation that in unrealized before `epoch_`.
     * @param  account_ The account to get the balance for.
     * @param  epoch_   The epoch to get the balance at.
     * @return The balance of `account_` plus any inflation that in unrealized before `epoch_`.
     */
    function _getBalance(address account_, uint16 epoch_) internal view virtual override returns (uint240) {
        unchecked {
            return
                UIntMath.bound240(
                    uint256(super._getBalance(account_, epoch_)) + _getUnrealizedInflation(account_, epoch_)
                );
        }
    }

    /**
     * @dev    Returns the balance of `account_` at `epoch_` without any unrealized inflation.
     * @param  account_ The account to get the balance for.
     * @param  epoch_   The epoch to get the balance at.
     * @return The balance of `account_` at `epoch` without any unrealized inflation.
     */
    function _getBalanceWithoutUnrealizedInflation(
        address account_,
        uint16 epoch_
    ) internal view virtual returns (uint240) {
        return super._getBalance(account_, epoch_);
    }

    /**
     * @dev    Returns the inflation of `amount` due to participation inflation.
     * @param  amount_ The amount to determine inflation for.
     * @return The inflation of `amount` due to participation inflation.
     */
    function _getInflation(uint240 amount_) internal view returns (uint240) {
        unchecked {
            return uint240((uint256(amount_) * participationInflation) / ONE); // Cannot overflow.
        }
    }

    /**
     * @dev    Returns the epoch of the last sync of `account_` at or before `epoch_`.
     *         Override this function in order to return the "default"/starting epoch if the account has never synced.
     * @param  account_ The account to get the last sync for.
     * @param  epoch_   The epoch to get the last sync at or before.
     * @return The epoch of the last sync of `account_` at or before `epoch_`.
     */
    function _getLastSync(address account_, uint16 epoch_) internal view virtual returns (uint16) {
        uint256 index_ = _lastSyncs[account_].length;

        // Keep going back until we find the first snap with a startingEpoch less than or equal to `epoch_`. This snap
        // is the most recent to `epoch_`, so return its startingEpoch. If we exhaust the array, then it's 0.
        while (index_ > 0) {
            unchecked {
                --index_;
            }

            uint16 snapStartingEpoch_ = _unsafeAccess(_lastSyncs[account_], index_).startingEpoch;

            if (snapStartingEpoch_ <= epoch_) return snapStartingEpoch_;
        }

        return 0;
    }

    /**
     * @dev    Returns whether `delegatee_` has participated during the clock value `epoch_`.
     * @param  delegatee_ The account whose participation is being queried.
     * @param  epoch_     The epoch at which to determine participation.
     * @return Whether `delegatee_` has participated during the clock value `epoch_`.
     */
    function _hasParticipatedAt(address delegatee_, uint16 epoch_) internal view returns (bool) {
        VoidSnap[] storage voidSnaps_ = _participations[delegatee_];

        uint256 index_ = voidSnaps_.length;

        // Keep going back until we find the first snap with a startingEpoch less than or equal to `epoch_`.
        // If this snap's startingEpoch is equal to `epoch_`, it means the delegatee did participate in `epoch_`.
        // If this startingEpoch is less than `epoch_`, it means the delegatee did not participated in `epoch_`.
        // If we exhaust the array, then the delegatee never participated in any epoch prior to `epoch_`.
        while (index_ > 0) {
            unchecked {
                --index_;
            }

            uint16 snapStartingEpoch_ = _unsafeAccess(voidSnaps_, index_).startingEpoch;

            if (snapStartingEpoch_ > epoch_) continue;

            return snapStartingEpoch_ == epoch_;
        }

        return false;
    }

    /**
     * @dev    Returns the unrealized inflation for `account_` from their last sync to the epoch before `lastEpoch_`.
     * @param  account_   The account being queried.
     * @param  lastEpoch_ The last epoch at which to determine unrealized inflation, not inclusive.
     * @return inflation_ The total unrealized inflation that has yet to be synced.
     */
    function _getUnrealizedInflation(address account_, uint16 lastEpoch_) internal view returns (uint240 inflation_) {
        // The balance and delegatee the account had at the epoch are the same since the last sync (by definition).
        uint240 balance_ = _getBalanceWithoutUnrealizedInflation(account_, lastEpoch_);

        if (balance_ == 0) return 0; // No inflation if the account had no balance.

        address delegatee_ = _getDelegatee(account_, lastEpoch_); // Internal avoids `_revertIfNotPastTimepoint`.

        // NOTE: Starting from the epoch after the latest sync, before `lastEpoch_`.
        // NOTE: If account never synced (i.e. it never interacted with the contract nor received tokens or voting
        //       power), then `epoch_` will start at 0, which can result in a longer loop than needed. Inheriting
        //       contracts should override `_getLastSync` to return the most recent appropriate epoch for such an
        //       account, such as the epoch when the contract was deployed, some bootstrap epoch, etc.
        for (uint16 epoch_ = _getLastSync(account_, lastEpoch_); epoch_ < lastEpoch_; ++epoch_) {
            // Skip non-voting epochs and epochs when the delegatee did not participate.
            if (!_isVotingEpoch(epoch_) || !_hasParticipatedAt(delegatee_, epoch_)) continue;

            unchecked {
                uint256 inflatedBalance_ = uint256(balance_) + inflation_;

                // Cap inflation to `type(uint240).max`.
                if (inflatedBalance_ >= type(uint240).max) return type(uint240).max;

                uint256 newInflation_ = uint256(inflation_) + _getInflation(uint240(inflatedBalance_));

                // Cap inflation to `type(uint240).max`.
                if (newInflation_ >= type(uint240).max) return type(uint240).max;

                inflation_ = uint240(newInflation_); // Accumulate compounded inflation.
            }
        }
    }

    /// @dev Reverts if the current epoch is a voting epoch.
    function _revertIfInVoteEpoch() internal view {
        if (_isVotingEpoch(_clock())) revert VoteEpoch();
    }

    /// @dev Reverts if the current epoch is not a voting epoch.
    function _revertIfNotInVoteEpoch() internal view {
        if (!_isVotingEpoch(_clock())) revert NotVoteEpoch();
    }

    /**
     * @dev    Returns whether the clock value `epoch_` is a voting epoch or not.
     * @param  epoch_ Some clock value.
     * @return Whether the epoch is a voting epoch.
     */
    function _isVotingEpoch(uint16 epoch_) internal pure returns (bool) {
        return epoch_ % 2 == 1; // Voting epochs are odd numbered.
    }

    /**
     * @dev    Returns the VoidSnap in an array at a given index without doing bounds checking.
     * @param  voidSnaps_ The array of VoidSnaps to parse.
     * @param  index_     The index of the VoidSnap to return.
     * @return voidSnap_  The VoidSnap at `index_`.
     */
    function _unsafeAccess(
        VoidSnap[] storage voidSnaps_,
        uint256 index_
    ) internal pure returns (VoidSnap storage voidSnap_) {
        assembly {
            mstore(0, voidSnaps_.slot)
            voidSnap_.slot := add(keccak256(0, 0x20), index_)
        }
    }
}

/**
 * @title An instance of an EpochBasedInflationaryVoteToken delegating control to a Standard Governor, and enabling
 *        auctioning of the unowned inflated supply.
 */
interface IPowerToken is IEpochBasedInflationaryVoteToken {
    /******************************************************************************************************************\
    |                                                      Events                                                      |
    \******************************************************************************************************************/

    /**
     * @notice Emitted when `buyer` has bought `amount` tokens from the auction, as a total cash token value of `cost`.
     * @param  buyer  The address of account that bought tokens from the auction.
     * @param  amount The amount of tokens bought.
     * @param  cost   The total cash token cost of the purchase.
     */
    event Buy(address indexed buyer, uint240 amount, uint256 cost);

    /**
     * @notice Emitted when the cash token is queued to become `nextCashToken` at the start of epoch `startingEpoch`.
     * @param  startingEpoch The epoch number as a clock value in which the new cash token takes effect.
     * @param  nextCashToken The address of the cash token taking effect at `startingEpoch`.
     */
    event NextCashTokenSet(uint16 indexed startingEpoch, address indexed nextCashToken);

    /**
     * @notice Emitted when the target supply is queued to become `targetSupply` at the start of epoch `targetEpoch`.
     * @param  targetEpoch  The epoch number as a clock value in which the new target supply takes effect.
     * @param  targetSupply The target supply taking effect at `startingEpoch`.
     */
    event TargetSupplyInflated(uint16 indexed targetEpoch, uint240 indexed targetSupply);

    /******************************************************************************************************************\
    |                                                      Errors                                                      |
    \******************************************************************************************************************/

    /// @notice Revert message when the total supply of the bootstrap token is larger than `type(uint240).max`.
    error BootstrapSupplyTooLarge();

    /**
     * @notice Revert message when the amount available for auction is less than the minimum requested to buy.
     * @param  amountToAuction    The amount available for auction.
     * @param  minAmountRequested The minimum amount that was requested to buy.
     */
    error InsufficientAuctionSupply(uint240 amountToAuction, uint240 minAmountRequested);

    /// @notice Revert message when the Bootstrap Token specified in the constructor is address(0).
    error InvalidBootstrapTokenAddress();

    /// @notice Revert message when the Cash Token specified in the constructor is address(0).
    error InvalidCashTokenAddress();

    /// @notice Revert message when the Standard Governor specified in the constructor is address(0).
    error InvalidStandardGovernorAddress();

    /// @notice Revert message when the Vault specified in the constructor is address(0).
    error InvalidVaultAddress();

    /// @notice Revert message when the caller is not the Standard Governor.
    error NotStandardGovernor();

    /// @notice Revert message when a token transferFrom fails.
    error TransferFromFailed();

    /// @notice Revert message when auction calculations use zero as denominator.
    error DivisionByZero();

    /// @notice Revert message when divideUp math overflows.
    error DivideUpOverflow();

    /******************************************************************************************************************\
    |                                              Interactive Functions                                               |
    \******************************************************************************************************************/

    /**
     * @notice Allows a caller to buy `amount` tokens from the auction.
     * @param  minAmount   The minimum amount of tokens the caller is interested in buying.
     * @param  maxAmount   The maximum amount of tokens the caller is interested in buying.
     * @param  destination The address of the account to send the bought tokens.
     * @return amount      The amount of token bought.
     * @return cost        The total cash token cost of the purchase.
     */
    function buy(
        uint256 minAmount,
        uint256 maxAmount,
        address destination
    ) external returns (uint240 amount, uint256 cost);

    /// @notice Marks the next voting epoch as targeted for inflation.
    function markNextVotingEpochAsActive() external;

    /**
     * @notice Marks `delegatee` as having participated in the current epoch, thus receiving voting power inflation.
     * @param  delegatee The address of the account being marked as having participated.
     */
    function markParticipation(address delegatee) external;

    /**
     * @notice Queues the cash token that will take effect from the next epoch onward.
     * @param  nextCashToken The address of the cash token taking effect from the next epoch onward.
     */
    function setNextCashToken(address nextCashToken) external;

    /******************************************************************************************************************\
    |                                               View/Pure Functions                                                |
    \******************************************************************************************************************/

    /// @notice Returns the amount of tokens that can be bought in the auction.
    function amountToAuction() external view returns (uint240);

    /// @notice Returns the epoch from which token balances and voting powers are bootstrapped.
    function bootstrapEpoch() external view returns (uint16);

    /// @notice Returns the address of the token in which token balances and voting powers are bootstrapped.
    function bootstrapToken() external view returns (address);

    /// @notice Returns the address of the cash token required to buy from the token auction.
    function cashToken() external view returns (address);

    /**
     * @notice Returns the total cost, in cash token, of purchasing `amount` tokens from the auction.
     * @param  amount Some amount of tokens.
     * @return The total cost, in cash token, of `amount` tokens.
     */
    function getCost(uint256 amount) external view returns (uint256);

    /// @notice Returns the address of the Standard Governor.
    function standardGovernor() external view returns (address);

    //// @notice Returns the target supply, which helps determine the amount of tokens up for auction.
    function targetSupply() external view returns (uint256);

    /// @notice Returns the address of the Vault.
    function vault() external view returns (address);

    /// @notice Returns the initial supply of the token.
    function INITIAL_SUPPLY() external pure returns (uint240);
}

// NOTE: Balances and voting powers are bootstrapped from the bootstrap token, but delegations are not.
// NOTE: Bootstrapping only works with a bootstrap token that supports the same PureEpochs as the clock mode.

/**
 * @title An instance of an EpochBasedInflationaryVoteToken delegating control to a Standard Governor, and enabling
 *        auctioning of the unowned inflated supply.
 */
contract PowerToken is IPowerToken, EpochBasedInflationaryVoteToken {
    /// @dev The number of auction periods in an epoch.
    uint40 internal constant _AUCTION_PERIODS = 100;

    /// @inheritdoc IPowerToken
    uint240 public constant INITIAL_SUPPLY = 10_000;

    /// @inheritdoc IPowerToken
    address public immutable bootstrapToken;

    /// @inheritdoc IPowerToken
    address public immutable standardGovernor;

    /// @inheritdoc IPowerToken
    address public immutable vault;

    /// @inheritdoc IPowerToken
    uint16 public immutable bootstrapEpoch;

    /// @dev The total supply of the bootstrap token at the bootstrap epoch.
    uint240 internal immutable _bootstrapSupply;

    /// @dev The starting epoch of the next cash token.
    uint16 internal _nextCashTokenStartingEpoch;

    /// @dev The address of the cash token required to buy from the token auction.
    address internal _cashToken;

    /// @dev The address of the next cash token.
    address internal _nextCashToken;

    /// @dev The starting epoch of the next target supply.
    uint16 internal _nextTargetSupplyStartingEpoch;

    /// @dev The current target supply of the token.
    uint240 internal _targetSupply;

    /// @dev The next target supply of the token.
    uint240 internal _nextTargetSupply = INITIAL_SUPPLY;

    /// @notice Reverts if the caller is not the Standard Governor.
    modifier onlyStandardGovernor() {
        _revertIfNotStandardGovernor();
        _;
    }

    /**
     * @notice Constructs a new Power Token contract.
     * @param  bootstrapToken_   The address of the token to bootstrap balances and voting powers from.
     * @param  standardGovernor_ The address of the Standard Governor contract to delegate control to.
     * @param  cashToken_        The address of the token to auction the unowned inflated supply for.
     * @param  vault_            The address of the vault to transfer cash tokens to.
     */
    constructor(
        address bootstrapToken_,
        address standardGovernor_,
        address cashToken_,
        address vault_
    ) EpochBasedInflationaryVoteToken("Power Token", "POWER", 0, ONE / 10) {
        if ((bootstrapToken = bootstrapToken_) == address(0)) revert InvalidBootstrapTokenAddress();
        if ((standardGovernor = standardGovernor_) == address(0)) revert InvalidStandardGovernorAddress();
        if ((_nextCashToken = cashToken_) == address(0)) revert InvalidCashTokenAddress();
        if ((vault = vault_) == address(0)) revert InvalidVaultAddress();

        uint16 bootstrapEpoch_ = bootstrapEpoch = (_clock() - 1);
        uint256 bootstrapSupply_ = IEpochBasedVoteToken(bootstrapToken_).pastTotalSupply(bootstrapEpoch_);

        if (bootstrapSupply_ > type(uint240).max) revert BootstrapSupplyTooLarge();

        _bootstrapSupply = uint240(bootstrapSupply_);

        _addTotalSupply(INITIAL_SUPPLY);
    }

    /******************************************************************************************************************\
    |                                      External/Public Interactive Functions                                       |
    \******************************************************************************************************************/

    /// @inheritdoc IPowerToken
    function buy(
        uint256 minAmount_,
        uint256 maxAmount_,
        address destination_
    ) external returns (uint240 amount_, uint256 cost_) {
        uint240 amountToAuction_ = amountToAuction();
        uint240 safeMinAmount_ = UIntMath.safe240(minAmount_);
        uint240 safeMaxAmount_ = UIntMath.safe240(maxAmount_);

        amount_ = amountToAuction_ > safeMaxAmount_ ? safeMaxAmount_ : amountToAuction_;

        if (amount_ < safeMinAmount_) revert InsufficientAuctionSupply(amountToAuction_, safeMinAmount_);

        emit Buy(msg.sender, amount_, cost_ = getCost(amount_));

        // NOTE: Not calling `distribute` on vault since anyone can do it, anytime, and this contract should not need to
        //       know how the vault works
        if (!ERC20Helper.transferFrom(cashToken(), msg.sender, vault, cost_)) revert TransferFromFailed();

        _mint(destination_, amount_);
    }

    /// @inheritdoc IPowerToken
    function markNextVotingEpochAsActive() external onlyStandardGovernor {
        // The next voting epoch is the targetEpoch.
        uint16 currentEpoch_ = _clock();
        uint16 targetEpoch_ = currentEpoch_ + (_isVotingEpoch(currentEpoch_) ? 2 : 1);

        // If the current epoch is already on or after the `_nextTargetSupplyStartingEpoch`, then rotate the variables
        // and track the next `_nextTargetSupplyStartingEpoch`, else just overwrite `nextTargetSupply_` only.
        if (currentEpoch_ >= _nextTargetSupplyStartingEpoch) {
            _targetSupply = _nextTargetSupply;
            _nextTargetSupplyStartingEpoch = targetEpoch_;
        }

        // NOTE: Cap the next target supply at `type(uint240).max`.
        uint240 nextTargetSupply_ = _nextTargetSupply = UIntMath.bound240(
            uint256(_targetSupply) + (_targetSupply * participationInflation) / ONE
        );

        emit TargetSupplyInflated(targetEpoch_, nextTargetSupply_);
    }

    /// @inheritdoc IPowerToken
    function markParticipation(address delegatee_) external onlyStandardGovernor {
        _markParticipation(delegatee_);
    }

    /// @inheritdoc IPowerToken
    function setNextCashToken(address nextCashToken_) external onlyStandardGovernor {
        if (nextCashToken_ == address(0)) revert InvalidCashTokenAddress();

        // The next epoch is the targetEpoch.
        uint16 currentEpoch_ = _clock();
        uint16 targetEpoch_ = currentEpoch_ + 1;

        // If the current epoch is already on or after the `_nextCashTokenStartingEpoch`, then rotate the variables
        // and track the next `_nextCashTokenStartingEpoch`, else just overwrite `_nextCashToken` only.
        if (currentEpoch_ >= _nextCashTokenStartingEpoch) {
            _cashToken = _nextCashToken;
            _nextCashTokenStartingEpoch = targetEpoch_;
        }

        _nextCashToken = nextCashToken_;

        emit NextCashTokenSet(targetEpoch_, _nextCashToken);
    }

    /******************************************************************************************************************\
    |                                       External/Public View/Pure Functions                                        |
    \******************************************************************************************************************/

    /// @inheritdoc IPowerToken
    function amountToAuction() public view returns (uint240) {
        if (_isVotingEpoch(_clock())) return 0; // No auction during voting epochs.

        uint240 targetSupply_ = _getTargetSupply();
        uint240 totalSupply_ = _getTotalSupply(_clock());

        unchecked {
            return targetSupply_ > totalSupply_ ? targetSupply_ - totalSupply_ : 0;
        }
    }

    /// @inheritdoc IPowerToken
    function cashToken() public view returns (address) {
        return _clock() >= _nextCashTokenStartingEpoch ? _nextCashToken : _cashToken;
    }

    /// @inheritdoc IPowerToken
    function getCost(uint256 amount_) public view returns (uint256) {
        uint16 currentEpoch_ = _clock();

        uint40 timeRemaining_ = _isVotingEpoch(currentEpoch_)
            ? PureEpochs._EPOCH_PERIOD
            : PureEpochs.timeRemainingInCurrentEpoch();

        uint40 secondsPerPeriod_ = PureEpochs._EPOCH_PERIOD / _AUCTION_PERIODS;
        uint256 leftPoint_ = uint256(1) << (timeRemaining_ / secondsPerPeriod_); // Max is 1 << 100.
        uint40 remainder_ = timeRemaining_ % secondsPerPeriod_;

        /**
         * @dev Auction curve:
         *        - During every auction period (1/100th of an epoch) the price starts at some "leftPoint" and decreases
         *          linearly, with time, to some "rightPoint" (which is half of that "leftPoint"). This is done by
         *          computing the weighted average between the "leftPoint" and "rightPoint" for the time remaining in
         *          the auction period.
         *        - For the next next auction period, the new "leftPoint" is half of the previous period's "leftPoint"
         *          (which also equals the previous period's "rightPoint").
         *        - Combined, this results in the price decreasing by half every auction period at a macro level, but
         *          decreasing linearly at a micro-level during each period, without any jumps.
         *      Relative price computation:
         *        - Since the parameters of this auction are fixed forever (there are no mutable auction parameters and
         *          this is not an upgradeable contract), and the token supply is expected to increase relatively
         *          quickly and consistently, the result would be that the price Y for some Z% of the total supply would
         *          occur earlier and earlier in the auction.
         *        - Instead, the desired behavior is that after X seconds into the auction, there will be a price Y for
         *          some Z% of the total supply. In other words, it will always cost 572,662,306,133 cash tokens to buy
         *          1% of the previous epoch's total supply with 5 days left in the auction period.
         *        - To achieve this, the price is instead computed per basis point of the last epoch's total supply.
         */
        // NOTE: A good amount of this can be done unchecked, but not every step, so it would look messy.
        return
            _divideUp(
                UIntMath.safe240(amount_) *
                    ((remainder_ * leftPoint_) + ((secondsPerPeriod_ - remainder_) * (leftPoint_ >> 1))),
                uint256(secondsPerPeriod_) * _getTotalSupply(currentEpoch_ - 1)
            );
    }

    /// @inheritdoc IPowerToken
    function targetSupply() public view returns (uint256) {
        return _getTargetSupply();
    }

    /******************************************************************************************************************\
    |                                          Internal Interactive Functions                                          |
    \******************************************************************************************************************/

    /**
     * @dev   Bootstrap the account's balance and voting power from the bootstrap token.
     * @param account_ The account to bootstrap.
     */
    function _bootstrap(address account_) internal {
        if (_lastSyncs[account_].length != 0) return; // Skip if the account already has synced (and thus bootstrapped).

        // NOTE: Don't need add `_getUnrealizedInflation(account_)` here since all callers of `_bootstrap` also call
        //       `_sync`, which will handle that.
        uint240 bootstrapBalance_ = _getBootstrapBalance(account_, bootstrapEpoch);

        if (bootstrapBalance_ == 0) return;

        _addBalance(account_, bootstrapBalance_);
        _addVotingPower(account_, bootstrapBalance_);
    }

    /**
     * @dev   Delegate voting power from `delegator_` to `newDelegatee_`.
     * @param delegator_    The address of the account delegating voting power.
     * @param newDelegatee_ The address of the account receiving voting power.
     */
    function _delegate(address delegator_, address newDelegatee_) internal override {
        _bootstrap(delegator_);
        _bootstrap(newDelegatee_);

        // NOTE: Need to sync `newDelegatee_` to ensure `_markParticipation` does not overwrite its voting power.
        _sync(newDelegatee_);

        super._delegate(delegator_, newDelegatee_);
    }

    /**
     * @dev   Allows for the inflation of a delegatee's voting power (and total supply) up to one time per epoch.
     * @param delegatee_ The address of the account being marked as having participated.
     */
    function _markParticipation(address delegatee_) internal override {
        _bootstrap(delegatee_);
        super._markParticipation(delegatee_);
    }

    /**
     * @dev   Mint `amount_` tokens to `recipient_`.
     * @param recipient_ The address of the account to mint tokens to.
     * @param amount_    The amount of tokens to mint.
     */
    function _mint(address recipient_, uint256 amount_) internal override {
        _bootstrap(recipient_);
        super._mint(recipient_, amount_);
    }

    /**
     * @dev   Transfers `amount_` tokens from `sender_` to `recipient_`.
     * @param sender_    The address of the account to transfer tokens from.
     * @param recipient_ The address of the account to transfer tokens to.
     * @param amount_    The amount of tokens to transfer.
     */
    function _transfer(address sender_, address recipient_, uint256 amount_) internal override {
        _bootstrap(sender_);
        _bootstrap(recipient_);
        super._transfer(sender_, recipient_, amount_);
    }

    /******************************************************************************************************************\
    |                                           Internal View/Pure Functions                                           |
    \******************************************************************************************************************/

    /**
     * @dev    Returns the balance of `account_` plus any inflation that in unrealized before `epoch_`.
     * @param  account_ The account to get the balance for.
     * @param  epoch_   The epoch to get the balance at.
     * @return The balance of `account_` plus any inflation that in unrealized before `epoch_`.
     */
    function _getBalance(address account_, uint16 epoch_) internal view override returns (uint240) {
        // For epochs less than or equal to the bootstrap epoch, return the bootstrap balance at that epoch.
        if (epoch_ <= bootstrapEpoch) return _getBootstrapBalance(account_, epoch_);

        // If no snaps, return the bootstrap balance at the bootstrap epoch and unrealized inflation at the epoch.
        if (_balances[account_].length == 0) {
            unchecked {
                return
                    UIntMath.bound240(
                        uint256(_getBootstrapBalance(account_, bootstrapEpoch)) +
                            _getUnrealizedInflation(account_, epoch_)
                    );
            }
        }

        return super._getBalance(account_, epoch_);
    }

    /**
     * @dev    Returns the balance of `account_` at `epoch_` without any unrealized inflation.
     * @param  account_ The account to get the balance for.
     * @param  epoch_   The epoch to get the balance at.
     * @return The balance of `account_` at `epoch` without any unrealized inflation.
     */
    function _getBalanceWithoutUnrealizedInflation(
        address account_,
        uint16 epoch_
    ) internal view override returns (uint240) {
        // For epochs less than or equal to the bootstrap epoch, return the bootstrap balance at that epoch.
        if (epoch_ <= bootstrapEpoch) return _getBootstrapBalance(account_, epoch_);

        // If no snaps, return the bootstrap balance at the bootstrap epoch.
        if (_balances[account_].length == 0) return _getBootstrapBalance(account_, bootstrapEpoch);

        return super._getBalanceWithoutUnrealizedInflation(account_, epoch_);
    }

    /**
     * @dev    This is the portion of the initial supply commensurate with the account's portion of the bootstrap supply.
     * @param  account_ The account to get the bootstrap balance for.
     * @param  epoch_   The epoch to get the bootstrap balance at.
     * @return The bootstrap balance of `account_` at `epoch_`.
     */
    function _getBootstrapBalance(address account_, uint16 epoch_) internal view returns (uint240) {
        unchecked {
            // NOTE: Can safely cast `pastBalanceOf` since the constructor already establishes that the total supply of
            //       the bootstrap token is less than `type(uint240).max`. Can do math unchecked since
            //       `pastBalanceOf * INITIAL_SUPPLY <= type(uint256).max`.
            return
                (uint240(IEpochBasedVoteToken(bootstrapToken).pastBalanceOf(account_, epoch_)) * INITIAL_SUPPLY) /
                _bootstrapSupply;
        }
    }

    /**
     * @dev    Returns the total supply at `epoch_`.
     * @param  epoch_ The epoch to get the total supply at.
     * @return The total supply at `epoch_`.
     */
    function _getTotalSupply(uint16 epoch_) internal view override returns (uint240) {
        // For epochs before the bootstrap epoch return the initial supply.
        return epoch_ <= bootstrapEpoch ? INITIAL_SUPPLY : super._getTotalSupply(epoch_);
    }

    /**
     * @dev    Returns the amount of votes of `account_` plus any inflation that should be realized at `epoch_`.
     * @param  account_ The account to get the votes for.
     * @param  epoch_   The epoch to get the votes at.
     * @return The balance of votes of `account_` plus any inflation that should be realized at `epoch_`.
     */
    function _getVotes(address account_, uint16 epoch_) internal view override returns (uint240) {
        // For epochs less than or equal to the bootstrap epoch, return the bootstrap balance at that epoch.
        if (epoch_ <= bootstrapEpoch) return _getBootstrapBalance(account_, epoch_);

        // If no snaps, return the bootstrap balance at the bootstrap epoch and unrealized inflation at the epoch.
        if (_votingPowers[account_].length == 0) {
            unchecked {
                return
                    UIntMath.bound240(
                        uint256(_getBootstrapBalance(account_, bootstrapEpoch)) +
                            _getUnrealizedInflation(account_, epoch_)
                    );
            }
        }

        return super._getVotes(account_, epoch_);
    }

    /**
     * @dev    Returns the epoch of the last sync of `account_` at or before `epoch_`.
     * @param  account_ The account to get the last sync for.
     * @param  epoch_   The epoch to get the last sync at or before.
     * @return The epoch of the last sync of `account_` at or before `epoch_`.
     */
    function _getLastSync(address account_, uint16 epoch_) internal view override returns (uint16) {
        // If there are no LastSync snaps, return the bootstrap epoch.
        return (_lastSyncs[account_].length == 0) ? bootstrapEpoch : super._getLastSync(account_, epoch_);
    }

    /// @dev Returns the target supply of the token at the current epoch.
    function _getTargetSupply() internal view returns (uint240 targetSupply_) {
        return _clock() >= _nextTargetSupplyStartingEpoch ? _nextTargetSupply : _targetSupply;
    }

    /// @dev Reverts if the caller is not the Standard Governor.
    function _revertIfNotStandardGovernor() internal view {
        if (msg.sender != standardGovernor) revert NotStandardGovernor();
    }

    /**
     * @dev Helper function to calculate `x` / `y`, rounded up.
     * @dev Inspired by USM (https://github.com/usmfum/USM/blob/master/contracts/WadMath.sol)
     */
    function _divideUp(uint256 x, uint256 y) internal pure returns (uint256 z) {
        if (y == 0) revert DivisionByZero();

        z = (x * ONE) + y;

        if (z < x) revert DivideUpOverflow();

        unchecked {
            z = (z - 1) / y;
        }
    }
}

/// @title A Deterministic deployer of Power Token contracts using CREATE.
contract PowerTokenDeployer is IPowerTokenDeployer {
    /// @inheritdoc IPowerTokenDeployer
    address public immutable vault;

    /// @inheritdoc IPowerTokenDeployer
    address public immutable zeroGovernor;

    /// @inheritdoc IDeployer
    address public lastDeploy;

    /// @inheritdoc IDeployer
    uint256 public nonce;

    /// @notice Throws if called by any account other than the Zero Governor.
    modifier onlyZeroGovernor() {
        if (msg.sender != zeroGovernor) revert NotZeroGovernor();
        _;
    }

    /**
     * @notice Constructs a new PowerTokenDeployer contract.
     * @param  zeroGovernor_ The address of the ZeroGovernor contract.
     * @param  vault_        The address of the Vault contract.
     */
    constructor(address zeroGovernor_, address vault_) {
        if ((zeroGovernor = zeroGovernor_) == address(0)) revert InvalidZeroGovernorAddress();
        if ((vault = vault_) == address(0)) revert InvalidVaultAddress();
    }

    /**
     * @notice Deploys a new PowerToken contract.
     * @param  bootstrapToken_   The address of the BootstrapToken contract.
     * @param  standardGovernor_ The address of the StandardGovernor contract.
     * @param  cashToken_        The address of the CashToken contract.
     * @return The address of the deployed PowerToken contract.
     */
    function deploy(
        address bootstrapToken_,
        address standardGovernor_,
        address cashToken_
    ) external onlyZeroGovernor returns (address) {
        unchecked {
            ++nonce;
        }

        return lastDeploy = address(new PowerToken(bootstrapToken_, standardGovernor_, cashToken_, vault));
    }

    /// @inheritdoc IDeployer
    function nextDeploy() external view returns (address) {
        unchecked {
            return ContractHelper.getContractFrom(address(this), nonce + 1);
        }
    }
}


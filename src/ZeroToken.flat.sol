// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

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

/// @title A Deterministic deployer of Standard Governor contracts using CREATE.
interface IStandardGovernorDeployer is IDeployer {
    /******************************************************************************************************************\
    |                                                      Errors                                                      |
    \******************************************************************************************************************/

    /// @notice Revert message when the Registrar specified in the constructor is address(0).
    error InvalidRegistrarAddress();

    /// @notice Revert message when the Vault specified in the constructor is address(0).
    error InvalidVaultAddress();

    /// @notice Revert message when the Zero Governor specified in the constructor is address(0).
    error InvalidZeroGovernorAddress();

    /// @notice Revert message when the Zero Token specified in the constructor is address(0).
    error InvalidZeroTokenAddress();

    /// @notice Revert message when the caller is not the Zero Governor.
    error NotZeroGovernor();

    /******************************************************************************************************************\
    |                                              Interactive Functions                                               |
    \******************************************************************************************************************/

    /**
     * @notice Deploys a new instance of a Standard Governor.
     * @param  powerToken                       The address of some Power Token that will be used by voters.
     * @param  emergencyGovernor                The address of some Emergency Governor.
     * @param  cashToken                        The address of some Cash Token.
     * @param  proposalFee                      The proposal fee required to create proposals.
     * @param  maxTotalZeroRewardPerActiveEpoch The maximum amount of Zero Token rewarded per active epoch.
     * @return The address of the deployed Standard Governor.
     */
    function deploy(
        address powerToken,
        address emergencyGovernor,
        address cashToken,
        uint256 proposalFee,
        uint256 maxTotalZeroRewardPerActiveEpoch
    ) external returns (address);

    /******************************************************************************************************************\
    |                                               View/Pure Functions                                                |
    \******************************************************************************************************************/

    /// @notice Returns the address of the Registrar.
    function registrar() external view returns (address);

    /// @notice Returns the address of the Vault.
    function vault() external view returns (address);

    /// @notice Returns the address of the Zero Governor.
    function zeroGovernor() external view returns (address);

    /// @notice Returns the address of the Zero Token.
    function zeroToken() external view returns (address);
}

/**
 * @title An instance of an EpochBasedVoteToken delegating minting control to a Standard Governor, and enabling
 *        range queries for past balances, voting powers, delegations, and  total supplies.
 */
interface IZeroToken is IEpochBasedVoteToken {
    /******************************************************************************************************************\
    |                                                      Errors                                                      |
    \******************************************************************************************************************/

    /// @notice Revert message when the Standard Governor Deployer specified in the constructor is address(0).
    error InvalidStandardGovernorDeployerAddress();

    /**
     * @notice Revert message when the length of some accounts array does not equal the length of some balances array.
     * @param  accountsLength The length of the accounts array.
     * @param  balancesLength The length of the balances array.
     */
    error LengthMismatch(uint256 accountsLength, uint256 balancesLength);

    /// @notice Revert message when the caller is not the Standard Governor.
    error NotStandardGovernor();

    /// @notice Revert message when the start of an inclusive range query is larger than the end.
    error StartEpochAfterEndEpoch();

    /******************************************************************************************************************\
    |                                              Interactive Functions                                               |
    \******************************************************************************************************************/

    /**
     * @notice Mints `amount` token to `recipient`.
     * @param  recipient The address of the account receiving minted token.
     * @param  amount    The amount of token to mint.
     */
    function mint(address recipient, uint256 amount) external;

    /******************************************************************************************************************\
    |                                               View/Pure Functions                                                |
    \******************************************************************************************************************/

    /**
     * @notice Returns an array of voting powers of `account` between `startEpoch` and `endEpoch` past inclusive clocks.
     * @param  account    The address of some account.
     * @param  startEpoch The starting epoch number as a clock value.
     * @param  endEpoch   The ending epoch number as a clock value.
     * @return An array of voting powers, each relating to an epoch in the inclusive range.
     */
    function getPastVotes(
        address account,
        uint256 startEpoch,
        uint256 endEpoch
    ) external view returns (uint256[] memory);

    /**
     * @notice Returns an array of token balances of `account` between `startEpoch` and `endEpoch` past inclusive clocks.
     * @param  account    The address of some account.
     * @param  startEpoch The starting epoch number as a clock value.
     * @param  endEpoch   The ending epoch number as a clock value.
     * @return An array of token balances, each relating to an epoch in the inclusive range.
     */
    function pastBalancesOf(
        address account,
        uint256 startEpoch,
        uint256 endEpoch
    ) external view returns (uint256[] memory);

    /**
     * @notice Returns the delegatee of `account` between `startEpoch` and `endEpoch` past inclusive clocks.
     * @param  account    The address of some account.
     * @param  startEpoch The starting epoch number as a clock value.
     * @param  endEpoch   The ending epoch number as a clock value.
     * @return An array of delegatees, each relating to an epoch in the inclusive range.
     */
    function pastDelegates(
        address account,
        uint256 startEpoch,
        uint256 endEpoch
    ) external view returns (address[] memory);

    /**
     * @notice Returns an array of total token supplies between `startEpoch` and `endEpoch` clocks inclusively.
     * @param  startEpoch The starting epoch number as a clock value.
     * @param  endEpoch   The ending epoch number as a clock value.
     * @return An array of total supplies, each relating to an epoch in the inclusive range.
     */
    function pastTotalSupplies(uint256 startEpoch, uint256 endEpoch) external view returns (uint256[] memory);

    /// @notice Returns the address of the Standard Governor.
    function standardGovernor() external view returns (address);

    /// @notice Returns the address of the Standard Governor Deployer.
    function standardGovernorDeployer() external view returns (address);
}

/**
 * @title An instance of an EpochBasedVoteToken delegating minting control to a Standard Governor, and enabling
 *        range queries for past balances, voting powers, delegations, and  total supplies.
 */
contract ZeroToken is IZeroToken, EpochBasedVoteToken {
    /// @inheritdoc IZeroToken
    address public immutable standardGovernorDeployer;

    /// @dev Revert if the caller is not the Standard Governor.
    modifier onlyStandardGovernor() {
        if (msg.sender != standardGovernor()) revert NotStandardGovernor();
        _;
    }

    /**
     * @notice Constructs a new ZeroToken contract.
     * @param  standardGovernorDeployer_ The address of the StandardGovernorDeployer contract.
     * @param  initialAccounts_          The addresses of the accounts to mint tokens to.
     * @param  initialBalances_          The amounts of tokens to mint to the accounts.
     */
    constructor(
        address standardGovernorDeployer_,
        address[] memory initialAccounts_,
        uint256[] memory initialBalances_
    ) EpochBasedVoteToken("Zero Token", "ZERO", 6) {
        if ((standardGovernorDeployer = standardGovernorDeployer_) == address(0)) {
            revert InvalidStandardGovernorDeployerAddress();
        }

        uint256 accountsLength_ = initialAccounts_.length;
        uint256 balancesLength_ = initialBalances_.length;

        if (accountsLength_ != balancesLength_) revert LengthMismatch(accountsLength_, balancesLength_);

        for (uint256 index_; index_ < accountsLength_; ++index_) {
            _mint(initialAccounts_[index_], initialBalances_[index_]);
        }
    }

    /******************************************************************************************************************\
    |                                      External/Public Interactive Functions                                       |
    \******************************************************************************************************************/

    /// @inheritdoc IZeroToken
    function mint(address recipient_, uint256 amount_) external onlyStandardGovernor {
        _mint(recipient_, amount_);
    }

    /******************************************************************************************************************\
    |                                       External/Public View/Pure Functions                                        |
    \******************************************************************************************************************/

    /// @inheritdoc IZeroToken
    function getPastVotes(
        address account_,
        uint256 startEpoch_,
        uint256 endEpoch_
    ) external view returns (uint256[] memory) {
        uint16 safeEndEpoch_ = UIntMath.safe16(endEpoch_);

        _revertIfNotPastTimepoint(safeEndEpoch_);

        return _getValuesBetween(_votingPowers[account_], UIntMath.safe16(startEpoch_), safeEndEpoch_);
    }

    /// @inheritdoc IZeroToken
    function pastBalancesOf(
        address account_,
        uint256 startEpoch_,
        uint256 endEpoch_
    ) external view returns (uint256[] memory) {
        uint16 safeEndEpoch_ = UIntMath.safe16(endEpoch_);

        _revertIfNotPastTimepoint(safeEndEpoch_);

        return _getValuesBetween(_balances[account_], UIntMath.safe16(startEpoch_), safeEndEpoch_);
    }

    /// @inheritdoc IZeroToken
    function pastDelegates(
        address account_,
        uint256 startEpoch_,
        uint256 endEpoch_
    ) external view returns (address[] memory) {
        uint16 safeEndEpoch_ = UIntMath.safe16(endEpoch_);

        _revertIfNotPastTimepoint(safeEndEpoch_);

        return _getDelegateesBetween(account_, UIntMath.safe16(startEpoch_), safeEndEpoch_);
    }

    /// @inheritdoc IZeroToken
    function pastTotalSupplies(uint256 startEpoch_, uint256 endEpoch_) external view returns (uint256[] memory) {
        uint16 safeEndEpoch_ = UIntMath.safe16(endEpoch_);

        _revertIfNotPastTimepoint(safeEndEpoch_);

        return _getValuesBetween(_totalSupplies, UIntMath.safe16(startEpoch_), safeEndEpoch_);
    }

    /// @inheritdoc IZeroToken
    function standardGovernor() public view returns (address) {
        return IStandardGovernorDeployer(standardGovernorDeployer).lastDeploy();
    }

    /******************************************************************************************************************\
    |                                           Internal View/Pure Functions                                           |
    \******************************************************************************************************************/

    /**
     * @notice Returns the delegatees of `account_` between `startEpoch_` and `endEpoch_`.
     * @param  account_    The address of the account whose delegatees are being queried.
     * @param  startEpoch_ The epoch from which to start querying.
     * @param  endEpoch_   The epoch at which to stop querying.
     * @return delegatees_ The delegatees of `account_` between `startEpoch_` and `endEpoch_`.
     */
    function _getDelegateesBetween(
        address account_,
        uint16 startEpoch_,
        uint16 endEpoch_
    ) internal view returns (address[] memory delegatees_) {
        if (startEpoch_ > endEpoch_) revert StartEpochAfterEndEpoch();

        uint16 epochsIndex_ = endEpoch_ - startEpoch_ + 1;

        delegatees_ = new address[](epochsIndex_);

        AccountSnap[] storage accountSnaps_ = _delegatees[account_];

        uint256 snapIndex_ = accountSnaps_.length;

        // Keep going back as long as the epoch is greater or equal to the previous AccountSnap's startingEpoch.
        while (snapIndex_ > 0) {
            unchecked {
                --snapIndex_;
            }

            AccountSnap storage accountSnap_ = _unsafeAccess(accountSnaps_, snapIndex_);
            uint16 snapStartingEpoch_ = accountSnap_.startingEpoch;

            // Keep checking if the AccountSnap's startingEpoch is applicable to the current and decrementing epoch.
            while (snapStartingEpoch_ <= endEpoch_) {
                unchecked {
                    --epochsIndex_;
                }

                delegatees_[epochsIndex_] = _getDefaultIfZero(accountSnap_.account, account_);

                if (epochsIndex_ == 0) return delegatees_;

                unchecked {
                    --endEpoch_;
                }
            }
        }

        // Set the remaining delegatee values (from before any accountSnaps existed) to the account itself.
        while (epochsIndex_ > 0) {
            unchecked {
                delegatees_[--epochsIndex_] = account_;
            }
        }
    }

    /**
     * @notice Returns the values of `amountSnaps_` between `startEpoch_` and `endEpoch_`.
     * @param  amountSnaps_ The array of AmountSnaps to query.
     * @param  startEpoch_  The epoch from which to start querying.
     * @param  endEpoch_    The epoch at which to stop querying.
     * @return values_      The values of `amountSnaps_` between `startEpoch_` and `endEpoch_`.
     */
    function _getValuesBetween(
        AmountSnap[] storage amountSnaps_,
        uint16 startEpoch_,
        uint16 endEpoch_
    ) internal view returns (uint256[] memory values_) {
        if (startEpoch_ > endEpoch_) revert StartEpochAfterEndEpoch();

        uint16 epochsIndex_ = endEpoch_ - startEpoch_ + 1;

        values_ = new uint256[](epochsIndex_);

        uint256 snapIndex_ = amountSnaps_.length;

        // Keep going back as long as the epoch is greater or equal to the previous AmountSnap's startingEpoch.
        while (snapIndex_ > 0) {
            unchecked {
                --snapIndex_;
            }

            AmountSnap storage amountSnap_ = _unsafeAccess(amountSnaps_, snapIndex_);

            uint256 snapStartingEpoch_ = amountSnap_.startingEpoch;

            // Keep checking if the AmountSnap's startingEpoch is applicable to the current and decrementing epoch.
            while (snapStartingEpoch_ <= endEpoch_) {
                unchecked {
                    --epochsIndex_;
                }

                values_[epochsIndex_] = amountSnap_.amount;

                if (epochsIndex_ == 0) return values_;

                unchecked {
                    --endEpoch_;
                }
            }
        }
    }
}


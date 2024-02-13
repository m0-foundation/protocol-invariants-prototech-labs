// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

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

/// @title TTG (Two Token Governance) Registrar interface.
interface ITTGRegistrar {
    /**
     * @notice Key value pair getter.
     * @param  key The key to get the value of.
     * @return value The value of the key.
     */
    function get(bytes32 key) external view returns (bytes32 value);

    /**
     * @notice Checks if the list contains the account.
     * @param  list The list to check.
     * @param  account The account to check.
     * @return True if the list contains the account, false otherwise.
     */
    function listContains(bytes32 list, address account) external view returns (bool);

    /// @notice Returns the vault contract address.
    function vault() external view returns (address);
}

/**
 * @title Library to read TTG (Two Token Governance) Registrar contract parameters.
 * @author M^0 Labs
 */
library TTGRegistrarReader {
    /// @notice The name of parameter in TTG that defines the base earner rate.
    bytes32 internal constant BASE_EARNER_RATE = "base_earner_rate";

    /// @notice The name of parameter in TTG that defines the base minter rate.
    bytes32 internal constant BASE_MINTER_RATE = "base_minter_rate";

    /// @notice The name of parameter in TTG that defines the earner rate model contract.
    bytes32 internal constant EARNER_RATE_MODEL = "earner_rate_model";

    /// @notice The earners list name in TTG.
    bytes32 internal constant EARNERS_LIST = "earners";

    /// @notice The earners list name in TTG.
    bytes32 internal constant EARNERS_LIST_IGNORED = "earners_list_ignored";

    /// @notice The name of parameter in TTG that defines the time to wait for mint request to be processed
    bytes32 internal constant MINT_DELAY = "mint_delay";

    /// @notice The name of parameter in TTG that defines the mint ratio.
    bytes32 internal constant MINT_RATIO = "mint_ratio"; // bps

    /// @notice The name of parameter in TTG that defines the time while mint request can still be processed
    bytes32 internal constant MINT_TTL = "mint_ttl";

    /// @notice The name of parameter in TTG that defines the time to freeze minter
    bytes32 internal constant MINTER_FREEZE_TIME = "minter_freeze_time";

    /// @notice The name of parameter in TTG that defines the minter rate model contract.
    bytes32 internal constant MINTER_RATE_MODEL = "minter_rate_model";

    /// @notice The minters list name in TTG.
    bytes32 internal constant MINTERS_LIST = "minters";

    /// @notice The name of parameter in TTG that defines the penalty rate.
    bytes32 internal constant PENALTY_RATE = "penalty_rate";

    /// @notice The name of parameter in TTG that required interval to update collateral.
    bytes32 internal constant UPDATE_COLLATERAL_INTERVAL = "updateCollateral_interval";

    /// @notice The name of parameter that defines number of signatures required for successful collateral update
    bytes32 internal constant UPDATE_COLLATERAL_VALIDATOR_THRESHOLD = "updateCollateral_threshold";

    /// @notice The validators list name in TTG.
    bytes32 internal constant VALIDATORS_LIST = "validators";

    /// @notice Gets the base earner rate.
    function getBaseEarnerRate(address registrar_) internal view returns (uint256) {
        return uint256(_get(registrar_, BASE_EARNER_RATE));
    }

    /// @notice Gets the base minter rate.
    function getBaseMinterRate(address registrar_) internal view returns (uint256) {
        return uint256(_get(registrar_, BASE_MINTER_RATE));
    }

    /// @notice Gets the earner rate model contract address.
    function getEarnerRateModel(address registrar_) internal view returns (address) {
        return toAddress(_get(registrar_, EARNER_RATE_MODEL));
    }

    /// @notice Gets the mint delay.
    function getMintDelay(address registrar_) internal view returns (uint256) {
        return uint256(_get(registrar_, MINT_DELAY));
    }

    /// @notice Gets the minter freeze time.
    function getMinterFreezeTime(address registrar_) internal view returns (uint256) {
        return uint256(_get(registrar_, MINTER_FREEZE_TIME));
    }

    /// @notice Gets the minter rate model contract address.
    function getMinterRateModel(address registrar_) internal view returns (address) {
        return toAddress(_get(registrar_, MINTER_RATE_MODEL));
    }

    /// @notice Gets the mint TTL.
    function getMintTTL(address registrar_) internal view returns (uint256) {
        return uint256(_get(registrar_, MINT_TTL));
    }

    /// @notice Gets the mint ratio.
    function getMintRatio(address registrar_) internal view returns (uint256) {
        return uint256(_get(registrar_, MINT_RATIO));
    }

    /// @notice Gets the update collateral interval.
    function getUpdateCollateralInterval(address registrar_) internal view returns (uint256) {
        return uint256(_get(registrar_, UPDATE_COLLATERAL_INTERVAL));
    }

    /// @notice Gets the update collateral validator threshold.
    function getUpdateCollateralValidatorThreshold(address registrar_) internal view returns (uint256) {
        return uint256(_get(registrar_, UPDATE_COLLATERAL_VALIDATOR_THRESHOLD));
    }

    /// @notice Checks if the given earner is approved.
    function isApprovedEarner(address registrar_, address earner_) internal view returns (bool) {
        return _contains(registrar_, EARNERS_LIST, earner_);
    }

    /// @notice Checks if the `earners_list_ignored` exists.
    function isEarnersListIgnored(address registrar_) internal view returns (bool) {
        return _get(registrar_, EARNERS_LIST_IGNORED) != bytes32(0);
    }

    /// @notice Checks if the given minter is approved.
    function isApprovedMinter(address registrar_, address minter_) internal view returns (bool) {
        return _contains(registrar_, MINTERS_LIST, minter_);
    }

    /// @notice Checks if the given validator is approved.
    function isApprovedValidator(address registrar_, address validator_) internal view returns (bool) {
        return _contains(registrar_, VALIDATORS_LIST, validator_);
    }

    /// @notice Gets the penalty rate.
    function getPenaltyRate(address registrar_) internal view returns (uint256) {
        return uint256(_get(registrar_, PENALTY_RATE));
    }

    /// @notice Gets the vault contract address.
    function getVault(address registrar_) internal view returns (address) {
        return ITTGRegistrar(registrar_).vault();
    }

    /// @notice Converts given bytes32 to address.
    function toAddress(bytes32 input_) internal pure returns (address) {
        return address(uint160(uint256(input_)));
    }

    /// @notice Checks if the given list contains the given account.
    function _contains(address registrar_, bytes32 listName_, address account_) private view returns (bool) {
        return ITTGRegistrar(registrar_).listContains(listName_, account_);
    }

    /// @notice Gets the value of the given key.
    function _get(address registrar_, bytes32 key_) private view returns (bytes32) {
        return ITTGRegistrar(registrar_).get(key_);
    }
}

/// @title Continuous Indexing Interface.
interface IContinuousIndexing {
    event IndexUpdated(uint128 indexed index, uint32 indexed rate);

    /// @notice The current index that would be written to storage if `updateIndex` is called.
    function currentIndex() external view returns (uint128);

    /// @notice The latest updated index.
    function latestIndex() external view returns (uint128);

    /// @notice The latest timestamp when the index was updated.
    function latestUpdateTimestamp() external view returns (uint40);

    /**
     * @notice Updates the latest index and latest accrual time in storage.
     * @return index The new stored index for computing present amounts from principal amounts.
     */
    function updateIndex() external returns (uint128);
}

/// @title M Token Interface.
interface IMToken is IContinuousIndexing, IERC20Extended {
    /******************************************************************************************************************\
    |                                                     Errors                                                       |
    \******************************************************************************************************************/

    /// @notice Emitted when principal of total supply (earning and non-earning) will overflow a `type(uint112).max`.
    error OverflowsPrincipalOfTotalSupply();

    /// @notice Emitted when calling `startEarningOnBehalfOf` for an account that has not allowed the start of earning on their behalf.
    error HasNotAllowedEarningOnBehalf();

    /// @notice Emitted when calling `stopEarning` for an account approved as earner by TTG.
    error IsApprovedEarner();

    /// @notice Emitted when calling `startEarning` for an account not approved as earner by TTG.
    error NotApprovedEarner();

    /// @notice Emitted when calling `mint`, `burn` not by Minter Gateway.
    error NotMinterGateway();

    ///  @notice Emitted in constructor if Minter Gateway is 0x0.
    error ZeroMinterGateway();

    ///  @notice Emitted in constructor if TTG Registrar is 0x0.
    error ZeroTTGRegistrar();

    /******************************************************************************************************************\
    |                                                     Events                                                       |
    \******************************************************************************************************************/

    /// @notice Emitted when account starts being an M earner.
    event StartedEarning(address indexed account);

    /// @notice Emitted when account stops being an M earner.
    event StoppedEarning(address indexed account);

    /// @notice Emitted when account has allowed anyone else to enable their earning.
    event AllowedEarningOnBehalf(address indexed account);

    /// @notice Emitted when account has disallowed anyone else from enabling their earning.
    event DisallowedEarningOnBehalf(address indexed account);

    /******************************************************************************************************************\
    |                                         External Interactive Functions                                           |
    \******************************************************************************************************************/

    /**
     * @notice Mints tokens.
     * @param  account The address of account to mint to.
     * @param  amount  The amount of M Token to mint.
     */
    function mint(address account, uint256 amount) external;

    /**
     * @notice Burns tokens.
     * @param  account The address of account to burn from.
     * @param  amount  The amount of M Token to burn.
     */
    function burn(address account, uint256 amount) external;

    /// @notice Starts earning for caller if allowed by TTG.
    function startEarning() external;

    /**
     * @notice Starts earning for account if allowed by TTG.
     * @param account The address of account to start earning for.
     */
    function startEarningOnBehalfOf(address account) external;

    /// @notice Stops earning for caller.
    function stopEarning() external;

    /**
     * @notice Stops earning for account.
     * @param  account The address of account to stop earning for.
     */
    function stopEarningOnBehalfOf(address account) external;

    /// @notice Allow anyone to call `startEarning` on behalf of the caller.
    function allowEarningOnBehalf() external;

    /// @notice Disallow anyone to call `startEarning` on behalf of the caller.
    function disallowEarningOnBehalf() external;

    /******************************************************************************************************************\
    |                                          External View/Pure Functions                                            |
    \******************************************************************************************************************/

    /// @notice The address of the Minter Gateway contract.
    function minterGateway() external view returns (address);

    /// @notice The address of the TTG Registrar contract.
    function ttgRegistrar() external view returns (address);

    /// @notice The address of TTG approved earner rate model.
    function rateModel() external view returns (address);

    /// @notice The current value of earner rate in basis points.
    function earnerRate() external view returns (uint32);

    /// @notice The principal of an earner M token balance.
    function principalBalanceOf(address account) external view returns (uint240);

    /// @notice The principal of the total earning supply of M Token.
    function principalOfTotalEarningSupply() external view returns (uint112);

    /// @notice The total earning supply of M Token.
    function totalEarningSupply() external view returns (uint240);

    /// @notice The total non-earning supply of M Token.
    function totalNonEarningSupply() external view returns (uint240);

    /// @notice Checks if account is an earner.
    function isEarning(address account) external view returns (bool);

    /// @notice Checks if account has allowed the start of earning on their behalf.
    function hasAllowedEarningOnBehalf(address account) external view returns (bool);
}

/// @title Rate Model Interface.
interface IRateModel {
    /**
     * @notice Returns the current value of the yearly rate
     * @dev    APY in BPS
     */
    function rate() external view returns (uint256);
}

/**
 * @title Arithmetic library with operations for calculating continuous indexing.
 * @author M^0 Labs
 */
library ContinuousIndexingMath {
    /// @notice Emitted when a division by zero occurs.
    error DivisionByZero();

    /// @notice The number of seconds in a year.
    uint32 internal constant SECONDS_PER_YEAR = 31_536_000;

    /// @notice 100% in basis points.
    uint16 internal constant BPS_SCALED_ONE = 1e4;

    /// @notice The scaling of rates in for exponent math.
    uint56 internal constant EXP_SCALED_ONE = 1e12;

    /**
     * @notice Helper function to calculate (`x` * `EXP_SCALED_ONE`) / `index`, rounded down.
     * @dev    Inspired by USM (https://github.com/usmfum/USM/blob/master/contracts/WadMath.sol)
     */
    function divideDown(uint240 x, uint128 index) internal pure returns (uint112 z) {
        if (index == 0) revert DivisionByZero();

        unchecked {
            // NOTE: While `uint256(x) * EXP_SCALED_ONE` can technically overflow, these divide/multiply functions are
            //       only used for the purpose of principal/present amount calculations for continuous indexing, and
            //       so for an `x` to be large enough to overflow this, it would have to be a possible result of
            //       `multiplyDown` or `multiplyUp`, which would already satisfy
            //       `uint256(x) * EXP_SCALED_ONE < type(uint256).max`.
            return UIntMath.safe112((uint256(x) * EXP_SCALED_ONE) / index);
        }
    }

    /**
     * @notice Helper function to calculate (`x` * `EXP_SCALED_ONE`) / `index`, rounded up.
     * @dev    Inspired by USM (https://github.com/usmfum/USM/blob/master/contracts/WadMath.sol)
     */
    function divideUp(uint240 x, uint128 index) internal pure returns (uint112 z) {
        if (index == 0) revert DivisionByZero();

        unchecked {
            // NOTE: While `uint256(x) * EXP_SCALED_ONE` can technically overflow, these divide/multiply functions are
            //       only used for the purpose of principal/present amount calculations for continuous indexing, and
            //       so for an `x` to be large enough to overflow this, it would have to be a possible result of
            //       `multiplyDown` or `multiplyUp`, which would already satisfy
            //       `uint256(x) * EXP_SCALED_ONE < type(uint256).max`.
            return UIntMath.safe112(((uint256(x) * EXP_SCALED_ONE) + index - 1) / index);
        }
    }

    /**
     * @notice Helper function to calculate (`x` * `index`) / `EXP_SCALED_ONE`, rounded down.
     * @dev    Inspired by USM (https://github.com/usmfum/USM/blob/master/contracts/WadMath.sol)
     */
    function multiplyDown(uint112 x, uint128 index) internal pure returns (uint240 z) {
        unchecked {
            return uint240((uint256(x) * index) / EXP_SCALED_ONE);
        }
    }

    /**
     * @notice Helper function to calculate (`x` * `index`) / `EXP_SCALED_ONE`, rounded up.
     * @dev    Inspired by USM (https://github.com/usmfum/USM/blob/master/contracts/WadMath.sol)
     */
    function multiplyUp(uint112 x, uint128 index) internal pure returns (uint240 z) {
        unchecked {
            return uint240(((uint256(x) * index) + (EXP_SCALED_ONE - 1)) / EXP_SCALED_ONE);
        }
    }

    /**
     * @notice Helper function to calculate (`index` * `deltaIndex`) / `EXP_SCALED_ONE`, rounded down.
     * @dev    Inspired by USM (https://github.com/usmfum/USM/blob/master/contracts/WadMath.sol)
     */
    function multiplyIndices(uint128 index, uint48 deltaIndex) internal pure returns (uint128 z) {
        unchecked {
            // NOTE: While `multiplyUp` can mostly result in additional continuous compounding accuracy (mainly because
            //       Padé exponent approximations always results in a lower value, and `multiplyUp` artificially
            //       increases that value), for some smaller `r*t` values, it results in a higher effective index than
            //       the "ideal". While not really an issue, this "often lower than, but sometimes higher than, ideal
            //       index" may no be a good characteristic, and `multiplyUp` does costs a tiny bit more gas.
            // NOTE: While technically possible for the result to be greater than `type(uint128).max`, having an index
            //       greater than `type(uint128).max` is just not possible to support with this protocol and we can
            //       safely assume such an index will never occur.
            return UIntMath.safe128((uint256(index) * deltaIndex) / EXP_SCALED_ONE);
        }
    }

    /**
     * @notice Helper function to calculate e^rt (continuous compounding formula).
     * @dev    `uint64 yearlyRate` can accommodate 1000% interest per year.
     * @dev    `uint32 time` can accommodate 100 years.
     * @dev    `type(uint64).max * type(uint32).max / SECONDS_PER_YEAR` fits in a `uint72`.
     */
    function getContinuousIndex(uint64 yearlyRate, uint32 time) internal pure returns (uint48 index) {
        unchecked {
            // NOTE: Casting `uint256(yearlyRate) * time` to a `uint72` is safe because the largest value is
            //      `type(uint64).max * type(uint32).max / SECONDS_PER_YEAR`, which is less than `type(uint72).max`.
            // NOTE: Can replace `exponent` here with `exponentAssembly` for ~44 gas savings.
            return exponent(uint72((uint256(yearlyRate) * time) / SECONDS_PER_YEAR));
        }
    }

    /**
     * @notice Helper function to calculate y = e^x using R(4,4) Padé approximation:
     *           e(x) = (1 + x/2 + 3(x^2)/28 + x^3/84 + x^4/1680) / (1 - x/2 + 3(x^2)/28 - x^3/84 + x^4/1680)
     *           See: https://en.wikipedia.org/wiki/Pad%C3%A9_table
     *           See: https://www.wolframalpha.com/input?i=PadeApproximant%5Bexp%5Bx%5D%2C%7Bx%2C0%2C%7B4%2C+4%7D%7D%5D
     *         Despite itself being a whole number, `x` represents a real number scaled by `EXP_SCALED_ONE`, thus
     *         allowing for y = e^x where x is a real number.
     * @dev    Output `y` for a `uint72` input `x` will fit in `uint48`
     */
    function exponent(uint72 x) internal pure returns (uint48 y) {
        // NOTE: This can be done unchecked even for `x = type(uint72).max`.
        //       Verify by removing `unchecked` and running `test_exponent()`.
        unchecked {
            uint256 x2 = uint256(x) * x;

            // `additiveTerms` is `(1 + 3(x^2)/28 + x^4/1680)`, and scaled by `84e27`.
            // NOTE: `84e27` the cleanest and largest scalar, given `(additiveTerms + differentTerms) * 1e12` overflow.
            // NOTE: The resulting `(x2 * x2) / 20e21` term has been split up in order to avoid overflow of `x2 * x2`.
            uint256 additiveTerms = 84e27 + (9e3 * x2) + ((x2 / 2e11) * (x2 / 10e10));

            // `differentTerms` is `(- x/2 - x^3/84)`, but positive (will be subtracted later), and scaled by `84e27`.
            uint256 differentTerms = uint256(x) * (42e15 + (x2 / 1e9));

            // Result needs to be scaled by `1e12`.
            // NOTE: Can cast to `uint48` because contents can never be larger than `type(uint48).max` for any `x`.
            //       Max `y` is ~200e12, before falling off. See links above for reference.
            return uint48(((additiveTerms + differentTerms) * 1e12) / (additiveTerms - differentTerms));
        }
    }

    /**
     * @notice Helper function to calculate y = e^x using R(4,4) Padé approximation:
     *           e(x) = (1 + x/2 + 3(x^2)/28 + x^3/84 + x^4/1680) / (1 - x/2 + 3(x^2)/28 - x^3/84 + x^4/1680)
     *           See: https://en.wikipedia.org/wiki/Pad%C3%A9_table
     *           See: https://www.wolframalpha.com/input?i=PadeApproximant%5Bexp%5Bx%5D%2C%7Bx%2C0%2C%7B4%2C+4%7D%7D%5D
     *         Despite itself being a whole number, `x` represents a real number scaled by `EXP_SCALED_ONE`, thus
     *         allowing for y = e^x where x is a real number.
     * @dev    Output `y` for a `uint72` input `x` will fit in `uint48`
     */
    function exponentAssembly(uint72 x) internal pure returns (uint48 y) {
        // NOTE: This can be done unchecked even for `x = type(uint72).max`.
        /// @solidity memory-safe-assembly
        assembly {
            y := mul(x, x) // temporarily use y as x^2

            // `additiveTerms` is `(1 + 3(x^2)/28 + x^4/1680)`, and scaled by `84e27`.
            // NOTE: `84e27` the cleanest and largest scalar, given `(additiveTerms + differentTerms) * 1e12` overflow.
            // NOTE: The resulting `(x2 * x2) / 20e21` term has been split up in order to avoid overflow of `x2 * x2`.
            let a := add(
                0x10f6b2be4706a13fc20000000,
                add(mul(0x2328, y), mul(sdiv(y, 0x2e90edd000), sdiv(y, 0x174876e800)))
            )

            // `differentTerms` is `(- x/2 - x^3/84)`, but positive (will be subtracted later), and scaled by `84e27`.
            let d := mul(x, add(0x9536c708910000, sdiv(y, 0x3b9aca00)))

            // Result needs to be scaled by `1e12`.
            // NOTE: Can cast to `uint48` because contents can never be larger than `type(uint48).max` for any `x`.
            //       Max `y` is ~200e12, before falling off. See links above for reference.
            y := sdiv(mul(0xe8d4a51000, add(a, d)), sub(a, d))
        }
    }

    /**
     * @notice Helper function to convert 12-decimal representation to basis points.
     * @param  input The input in 12-decimal representation.
     * @return The output in basis points.
     */
    function convertToBasisPoints(uint64 input) internal pure returns (uint32) {
        unchecked {
            return uint32((uint256(input) * BPS_SCALED_ONE) / EXP_SCALED_ONE);
        }
    }

    /**
     * @notice Helper function to convert basis points to 12-decimal representation.
     * @param  input The input in basis points.
     * @return The output in 12-decimal representation.
     */
    function convertFromBasisPoints(uint32 input) internal pure returns (uint64) {
        unchecked {
            return uint64((uint256(input) * EXP_SCALED_ONE) / BPS_SCALED_ONE);
        }
    }
}

/**
 * @title Abstract Continuous Indexing Contract to handle rate/index updates in inheriting contracts.
 * @author M^0 Labs
 */
abstract contract ContinuousIndexing is IContinuousIndexing {
    /// @dev The latest updated index.
    uint128 internal _latestIndex;

    /// @dev The latest updated rate.
    uint32 internal _latestRate;

    /// @dev The latest timestamp when the index was updated.
    uint40 internal _latestUpdateTimestamp;

    /// @notice Constructs the ContinuousIndexing contract.
    constructor() {
        _latestIndex = ContinuousIndexingMath.EXP_SCALED_ONE;
        _latestUpdateTimestamp = uint40(block.timestamp);
    }

    /******************************************************************************************************************\
    |                                      External/Public Interactive Functions                                       |
    \******************************************************************************************************************/

    /// @inheritdoc IContinuousIndexing
    function updateIndex() public virtual returns (uint128 currentIndex_) {
        // NOTE: `_rate()` can depend indirectly on `_latestIndex` and `_latestUpdateTimestamp`, if the RateModel
        //       depends on earning balances/supply, which depends on `currentIndex()`, so only update them after this.
        uint32 rate_ = _rate();

        if (_latestUpdateTimestamp == block.timestamp && _latestRate == rate_) return _latestIndex;

        // NOTE: `currentIndex()` depends on `_latestRate`, so only update it after this.
        _latestIndex = currentIndex_ = currentIndex();
        _latestRate = rate_;
        _latestUpdateTimestamp = uint40(block.timestamp);

        emit IndexUpdated(currentIndex_, rate_);
    }

    /******************************************************************************************************************\
    |                                       External/Public View/Pure Functions                                        |
    \******************************************************************************************************************/

    /// @inheritdoc IContinuousIndexing
    function currentIndex() public view virtual returns (uint128) {
        // NOTE: safe to use unchecked here, since `block.timestamp` is always greater than `_latestUpdateTimestamp`.
        unchecked {
            return
                ContinuousIndexingMath.multiplyIndices(
                    _latestIndex,
                    ContinuousIndexingMath.getContinuousIndex(
                        ContinuousIndexingMath.convertFromBasisPoints(_latestRate),
                        uint32(block.timestamp - _latestUpdateTimestamp)
                    )
                );
        }
    }

    /// @inheritdoc IContinuousIndexing
    function latestIndex() public view virtual returns (uint128) {
        return _latestIndex;
    }

    /// @inheritdoc IContinuousIndexing
    function latestUpdateTimestamp() public view virtual returns (uint40) {
        return _latestUpdateTimestamp;
    }

    /******************************************************************************************************************\
    |                                           Internal View/Pure Functions                                           |
    \******************************************************************************************************************/

    /**
     * @dev    Returns the present amount (rounded down) given the principal amount and an index.
     * @param  principalAmount_ The principal amount.
     * @param  index_           An index.
     * @return The present amount rounded down.
     */
    function _getPresentAmountRoundedDown(uint112 principalAmount_, uint128 index_) internal pure returns (uint240) {
        return ContinuousIndexingMath.multiplyDown(principalAmount_, index_);
    }

    /**
     * @dev    Returns the present amount (rounded up) given the principal amount and an index.
     * @param  principalAmount_ The principal amount.
     * @param  index_           An index.
     * @return The present amount rounded up.
     */
    function _getPresentAmountRoundedUp(uint112 principalAmount_, uint128 index_) internal pure returns (uint240) {
        return ContinuousIndexingMath.multiplyUp(principalAmount_, index_);
    }

    /**
     * @dev    Returns the principal amount (rounded down) given the present amount, using the current index.
     * @param  presentAmount_ The present amount.
     * @return The principal amount rounded down.
     */
    function _getPrincipalAmountRoundedDown(uint240 presentAmount_) internal view returns (uint112) {
        return _getPrincipalAmountRoundedDown(presentAmount_, currentIndex());
    }

    /**
     * @dev    Returns the principal amount given the present amount, using the current index.
     * @param  presentAmount_ The present amount.
     * @param  index_         An index.
     * @return The principal amount rounded down.
     */
    function _getPrincipalAmountRoundedDown(uint240 presentAmount_, uint128 index_) internal pure returns (uint112) {
        return ContinuousIndexingMath.divideDown(presentAmount_, index_);
    }

    /**
     * @dev    Returns the principal amount (rounded up) given the present amount and an index.
     * @param  presentAmount_ The present amount.
     * @return The principal amount rounded up.
     */
    function _getPrincipalAmountRoundedUp(uint240 presentAmount_) internal view returns (uint112) {
        return _getPrincipalAmountRoundedUp(presentAmount_, currentIndex());
    }

    /**
     * @dev    Returns the principal amount given the present amount, using the current index.
     * @param  presentAmount_ The present amount.
     * @param  index_         An index.
     * @return The principal amount rounded up.
     */
    function _getPrincipalAmountRoundedUp(uint240 presentAmount_, uint128 index_) internal pure returns (uint112) {
        return ContinuousIndexingMath.divideUp(presentAmount_, index_);
    }

    /// @dev To be overridden by the inheriting contract to return the current rate.
    function _rate() internal view virtual returns (uint32);
}

/**
 * @title  MToken
 * @author M^0 Labs
 * @notice ERC20 M Token.
 */
contract MToken is IMToken, ContinuousIndexing, ERC20Extended {
    struct MBalance {
        bool isEarning;
        bool hasAllowedEarningOnBehalf;
        uint240 rawBalance; // balance (for a non earning account) or principal balance that accrued interest
    }

    /// @inheritdoc IMToken
    address public immutable minterGateway;

    /// @inheritdoc IMToken
    address public immutable ttgRegistrar;

    /// @dev The total amount of non earning M supply.
    uint240 public totalNonEarningSupply;

    /// @dev The principal of the total amount of earning M supply. totalEarningSupply = principal * currentIndex
    uint112 public principalOfTotalEarningSupply;

    /// @notice The balance of M for non-earner or principal of earning M balance for earners.
    mapping(address account => MBalance balance) internal _balances;

    /// @dev Modifier to check if caller is Minter Gateway.
    modifier onlyMinterGateway() {
        if (msg.sender != minterGateway) revert NotMinterGateway();

        _;
    }

    /**
     * @notice Constructs the M Token contract.
     * @param  ttgRegistrar_ The address of the TTG Registrar contract.
     * @param  minterGateway_     The address of Minter Gateway.
     */
    constructor(address ttgRegistrar_, address minterGateway_) ContinuousIndexing() ERC20Extended("M Token", "M", 6) {
        if ((ttgRegistrar = ttgRegistrar_) == address(0)) revert ZeroTTGRegistrar();
        if ((minterGateway = minterGateway_) == address(0)) revert ZeroMinterGateway();
    }

    /******************************************************************************************************************\
    |                                      External/Public Interactive Functions                                       |
    \******************************************************************************************************************/

    /// @inheritdoc IMToken
    function mint(address account_, uint256 amount_) external onlyMinterGateway {
        _mint(account_, amount_);
    }

    /// @inheritdoc IMToken
    function burn(address account_, uint256 amount_) external onlyMinterGateway {
        _burn(account_, amount_);
    }

    /// @inheritdoc IMToken
    function startEarning() external {
        _revertIfNotApprovedEarner(msg.sender);
        _startEarning(msg.sender);
    }

    /// @inheritdoc IMToken
    function startEarningOnBehalfOf(address account_) external {
        if (!_balances[account_].hasAllowedEarningOnBehalf) revert HasNotAllowedEarningOnBehalf();

        _revertIfNotApprovedEarner(account_);
        _startEarning(account_);
    }

    /// @inheritdoc IMToken
    function stopEarning() external {
        disallowEarningOnBehalf();
        _stopEarning(msg.sender);
    }

    /// @inheritdoc IMToken
    function stopEarningOnBehalfOf(address account_) external {
        if (_isApprovedEarner(account_)) revert IsApprovedEarner();

        _stopEarning(account_);
    }

    /// @inheritdoc IMToken
    function allowEarningOnBehalf() public {
        emit AllowedEarningOnBehalf(msg.sender);
        _balances[msg.sender].hasAllowedEarningOnBehalf = true;
    }

    /// @inheritdoc IMToken
    function disallowEarningOnBehalf() public {
        emit DisallowedEarningOnBehalf(msg.sender);
        _balances[msg.sender].hasAllowedEarningOnBehalf = false;
    }

    /******************************************************************************************************************\
    |                                       External/Public View/Pure Functions                                        |
    \******************************************************************************************************************/

    /// @inheritdoc IMToken
    function rateModel() public view returns (address rateModel_) {
        return TTGRegistrarReader.getEarnerRateModel(ttgRegistrar);
    }

    /// @inheritdoc IMToken
    function earnerRate() public view returns (uint32 earnerRate_) {
        return _latestRate;
    }

    /// @inheritdoc IMToken
    function totalEarningSupply() public view returns (uint240 totalEarningSupply_) {
        return _getPresentAmount(principalOfTotalEarningSupply);
    }

    /// @inheritdoc IERC20
    function totalSupply() external view returns (uint256 totalSupply_) {
        unchecked {
            return totalNonEarningSupply + totalEarningSupply();
        }
    }

    /// @inheritdoc IMToken
    function principalBalanceOf(address account_) external view returns (uint240 balance_) {
        MBalance storage mBalance_ = _balances[account_];

        return mBalance_.isEarning ? uint112(mBalance_.rawBalance) : 0; // Treat the raw balance as principal for earner.
    }

    /// @inheritdoc IERC20
    function balanceOf(address account_) external view returns (uint256 balance_) {
        MBalance storage mBalance_ = _balances[account_];

        return
            mBalance_.isEarning
                ? _getPresentAmount(uint112(mBalance_.rawBalance)) // Treat the raw balance as principal for earner.
                : mBalance_.rawBalance;
    }

    /// @inheritdoc IMToken
    function isEarning(address account_) external view returns (bool isEarning_) {
        return _balances[account_].isEarning;
    }

    /// @inheritdoc IMToken
    function hasAllowedEarningOnBehalf(address account_) external view returns (bool) {
        return _balances[account_].hasAllowedEarningOnBehalf;
    }

    /******************************************************************************************************************\
    |                                          Internal Interactive Functions                                          |
    \******************************************************************************************************************/

    /**
     * @dev   Adds principal to `_balances` of an earning account.
     * @param account_         The account to add principal to.
     * @param principalAmount_ The principal amount to add.
     */
    function _addEarningAmount(address account_, uint112 principalAmount_) internal {
        unchecked {
            _balances[account_].rawBalance += principalAmount_;
            principalOfTotalEarningSupply += principalAmount_;
        }
    }

    /**
     * @dev   Adds amount to `_balances` of a non-earning account.
     * @param account_ The account to add amount to.
     * @param amount_  The amount to add.
     */
    function _addNonEarningAmount(address account_, uint240 amount_) internal {
        unchecked {
            _balances[account_].rawBalance += amount_;
            totalNonEarningSupply += amount_;
        }
    }

    /**
     * @dev   Burns amount of earning or non-earning M from account.
     * @param account_ The account to burn from.
     * @param amount_  The present amount to burn.
     */
    function _burn(address account_, uint256 amount_) internal {
        emit Transfer(account_, address(0), amount_);

        if (_balances[account_].isEarning) {
            // NOTE: When burning a present amount, round the principal up in favor of the protocol.
            _subtractEarningAmount(account_, _getPrincipalAmountRoundedUp(UIntMath.safe240(amount_)));
            updateIndex();
        } else {
            _subtractNonEarningAmount(account_, UIntMath.safe240(amount_));
        }
    }

    /**
     * @dev   Mints amount of earning or non-earning M to account.
     * @param recipient_ The account to mint to.
     * @param amount_    The present amount to mint.
     */
    function _mint(address recipient_, uint256 amount_) internal {
        emit Transfer(address(0), recipient_, amount_);

        if (_balances[recipient_].isEarning) {
            // NOTE: When minting a present amount, round the principal down in favor of the protocol.
            _addEarningAmount(recipient_, _getPrincipalAmountRoundedDown(UIntMath.safe240(amount_)));
            updateIndex();
        } else {
            _addNonEarningAmount(recipient_, UIntMath.safe240(amount_));
        }

        if (
            principalOfTotalEarningSupply + _getPrincipalAmountRoundedDown(totalNonEarningSupply) >= type(uint112).max
        ) {
            revert OverflowsPrincipalOfTotalSupply();
        }
    }

    /**
     * @dev   Starts earning for account.
     * @param account_ The account to start earning for.
     */
    function _startEarning(address account_) internal {
        emit StartedEarning(account_);

        MBalance storage mBalance_ = _balances[account_];

        if (mBalance_.isEarning) return;

        mBalance_.isEarning = true;

        // Treat the raw balance as present amount for non earner.
        uint240 amount_ = _balances[account_].rawBalance;

        if (amount_ == 0) return;

        // NOTE: When converting a non-earning balance into an earning balance, round the principal down in favor of
        //       the Minter Gateway.
        uint112 principalAmount_ = _getPrincipalAmountRoundedDown(amount_);

        _balances[account_].rawBalance = principalAmount_;

        unchecked {
            principalOfTotalEarningSupply += principalAmount_;
            totalNonEarningSupply -= amount_;
        }

        updateIndex();
    }

    /**
     * @dev   Stops earning for account.
     * @param account_ The account to stop earning for.
     */
    function _stopEarning(address account_) internal {
        emit StoppedEarning(account_);

        MBalance storage mBalance_ = _balances[account_];

        if (!mBalance_.isEarning) return;

        mBalance_.isEarning = false;

        // Treat the raw balance as principal for earner.
        uint112 principalAmount_ = uint112(_balances[account_].rawBalance);

        if (principalAmount_ == 0) return;

        uint240 amount_ = _getPresentAmount(principalAmount_);

        _balances[account_].rawBalance = amount_;

        unchecked {
            totalNonEarningSupply += amount_;
            principalOfTotalEarningSupply -= principalAmount_;
        }

        updateIndex();
    }

    /**
     * @dev   Subtracts principal from `_balances` of an earning account.
     * @param account_         The account to subtract principal from.
     * @param principalAmount_ The principal amount to subtract.
     */
    function _subtractEarningAmount(address account_, uint112 principalAmount_) internal {
        _balances[account_].rawBalance -= principalAmount_;

        unchecked {
            principalOfTotalEarningSupply -= principalAmount_;
        }
    }

    /**
     * @dev   Subtracts amount from `_balances` of a non-earning account.
     * @param account_ The account to subtract amount from.
     * @param amount_  The amount to subtract.
     */
    function _subtractNonEarningAmount(address account_, uint240 amount_) internal {
        _balances[account_].rawBalance -= amount_;

        unchecked {
            totalNonEarningSupply -= amount_;
        }
    }

    /**
     * @dev   Transfer M between both earning and non-earning accounts.
     * @param sender_    The account to transfer from. It can be either earning or non-earning account.
     * @param recipient_ The account to transfer to. It can be either earning or non-earning account.
     * @param amount_    The present amount to transfer.
     */
    function _transfer(address sender_, address recipient_, uint256 amount_) internal override {
        emit Transfer(sender_, recipient_, amount_);

        uint240 safeAmount_ = UIntMath.safe240(amount_);

        bool senderIsEarning_ = _balances[sender_].isEarning; // Only using the sender's earning status more than once.

        // If this is an in-kind transfer, then...
        if (senderIsEarning_ == _balances[recipient_].isEarning) {
            // NOTE: When subtracting a present amount from an earner, round the principal up in favor of the protocol.
            return
                _transferAmountInKind( // perform an in-kind transfer with...
                    sender_,
                    recipient_,
                    senderIsEarning_ ? _getPrincipalAmountRoundedUp(safeAmount_) : safeAmount_ // the appropriate amount.
                );
        }

        // If this is not an in-kind transfer, then...
        if (senderIsEarning_) {
            // either the sender is earning and the recipient is not, or...
            // NOTE: When subtracting a present amount from an earner, round the principal up in favor of the protocol.
            _subtractEarningAmount(sender_, _getPrincipalAmountRoundedUp(safeAmount_));
            _addNonEarningAmount(recipient_, safeAmount_);
        } else {
            // the sender is not earning and the recipient is.
            // NOTE: When adding a present amount to an earner, round the principal down in favor of the protocol.
            _subtractNonEarningAmount(sender_, safeAmount_);
            _addEarningAmount(recipient_, _getPrincipalAmountRoundedDown(safeAmount_));
        }

        updateIndex();
    }

    /**
     * @dev   Transfer M between same earning status accounts.
     * @param sender_    The account to transfer from.
     * @param recipient_ The account to transfer to.
     * @param amount_    The amount (present or principal) to transfer.
     */
    function _transferAmountInKind(address sender_, address recipient_, uint240 amount_) internal {
        _balances[sender_].rawBalance -= amount_;

        unchecked {
            _balances[recipient_].rawBalance += amount_;
        }
    }

    /******************************************************************************************************************\
    |                                           Internal View/Pure Functions                                           |
    \******************************************************************************************************************/

    /**
     * @dev   Returns the present amount (rounded down) given the principal amount, using the current index.
     *        All present amounts are rounded down in favor of the protocol.
     * @param principalAmount_ The principal amount.
     */
    function _getPresentAmount(uint112 principalAmount_) internal view returns (uint240 amount_) {
        return _getPresentAmount(principalAmount_, currentIndex());
    }

    /**
     * @dev   Returns the present amount (rounded down) given the principal amount and an index.
     *        All present amounts are rounded down in favor of the protocol, since they are assets.
     * @param principalAmount_ The principal amount.
     * @param index_           An index
     */
    function _getPresentAmount(uint112 principalAmount_, uint128 index_) internal pure returns (uint240 amount_) {
        return _getPresentAmountRoundedDown(principalAmount_, index_);
    }

    /**
     * @dev    Checks if earner was approved by TTG.
     * @param  account_    The account to check.
     * @return isApproved_ True if approved, false otherwise.
     */
    function _isApprovedEarner(address account_) internal view returns (bool isApproved_) {
        return
            TTGRegistrarReader.isEarnersListIgnored(ttgRegistrar) ||
            TTGRegistrarReader.isApprovedEarner(ttgRegistrar, account_);
    }

    /**
     * @dev    Gets the current earner rate from TTG approved rate model contract.
     * @return rate_ The current earner rate.
     */
    function _rate() internal view override returns (uint32 rate_) {
        (bool success_, bytes memory returnData_) = rateModel().staticcall(
            abi.encodeWithSelector(IRateModel.rate.selector)
        );

        rate_ = (success_ && returnData_.length >= 32) ? UIntMath.bound32(abi.decode(returnData_, (uint256))) : 0;
    }

    /**
     * @dev   Reverts if account is not approved earner.
     * @param account_ The account to check.
     */
    function _revertIfNotApprovedEarner(address account_) internal view {
        if (!_isApprovedEarner(account_)) revert NotApprovedEarner();
    }
}


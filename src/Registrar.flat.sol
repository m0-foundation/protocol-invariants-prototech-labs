// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

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

/// @title A Deterministic deployer of Emergency Governor contracts using CREATE.
interface IEmergencyGovernorDeployer is IDeployer {
    /******************************************************************************************************************\
    |                                                      Errors                                                      |
    \******************************************************************************************************************/

    /// @notice Revert message when the Registrar specified in the constructor is address(0).
    error InvalidRegistrarAddress();

    /// @notice Revert message when the Zero Governor specified in the constructor is address(0).
    error InvalidZeroGovernorAddress();

    /// @notice Revert message when the caller is not the Zero Governor.
    error NotZeroGovernor();

    /******************************************************************************************************************\
    |                                              Interactive Functions                                               |
    \******************************************************************************************************************/

    /**
     * @notice Deploys a new instance of an Emergency Governor.
     * @param  powerToken       The address of some Power Token that will be used by voters.
     * @param  standardGovernor The address of some Standard Governor.
     * @param  thresholdRatio   The threshold ratio to use for proposals.
     * @return The address of the deployed Emergency Governor.
     */
    function deploy(address powerToken, address standardGovernor, uint16 thresholdRatio) external returns (address);

    /******************************************************************************************************************\
    |                                               View/Pure Functions                                                |
    \******************************************************************************************************************/

    /// @notice Returns the address of the Registrar.
    function registrar() external view returns (address);

    /// @notice Returns the address of the Zero Governor.
    function zeroGovernor() external view returns (address);
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

/// @title A book of record of SPOG-specific contracts and arbitrary key-value pairs and lists.
interface IRegistrar {
    /******************************************************************************************************************\
    |                                                      Events                                                      |
    \******************************************************************************************************************/

    /**
     * @notice Emitted when `account` is added to `list`.
     * @param  list    The key for the list.
     * @param  account The address of the added account.
     */
    event AddressAddedToList(bytes32 indexed list, address indexed account);

    /**
     * @notice Emitted when `account` is removed from `list`.
     * @param  list    The key for the list.
     * @param  account The address of the removed account.
     */
    event AddressRemovedFromList(bytes32 indexed list, address indexed account);

    /**
     * @notice Emitted when `key` is set to `value`.
     * @param  key   The key.
     * @param  value The value.
     */
    event KeySet(bytes32 indexed key, bytes32 indexed value);

    /******************************************************************************************************************\
    |                                                      Errors                                                      |
    \******************************************************************************************************************/

    /// @notice Revert message when the Emergency Governor Deployer retrieved in the constructor is address(0).
    error InvalidEmergencyGovernorDeployerAddress();

    /// @notice Revert message when the Power Token Deployer retrieved in the constructor is address(0).
    error InvalidPowerTokenDeployerAddress();

    /// @notice Revert message when the Standard Governor Deployer retrieved in the constructor is address(0).
    error InvalidStandardGovernorDeployerAddress();

    /// @notice Revert message when the Vault retrieved in the constructor is address(0).
    error InvalidVaultAddress();

    /// @notice Revert message when the Vote Token retrieved in the constructor is address(0).
    error InvalidVoteTokenAddress();

    /// @notice Revert message when the Zero Governor specified in the constructor is address(0).
    error InvalidZeroGovernorAddress();

    /// @notice Revert message when the caller is not the Standard Governor nor the Emergency Governor.
    error NotStandardOrEmergencyGovernor();

    /******************************************************************************************************************\
    |                                              Interactive Functions                                               |
    \******************************************************************************************************************/

    /**
     * @notice Adds `account` to `list`.
     * @param  list    The key for some list.
     * @param  account The address of some account to be added.
     */
    function addToList(bytes32 list, address account) external;

    /**
     * @notice Removes `account` from `list`.
     * @param  list    The key for some list.
     * @param  account The address of some account to be removed.
     */
    function removeFromList(bytes32 list, address account) external;

    /**
     * @notice Sets `key` to `value`.
     * @param  key   Some key.
     * @param  value Some value.
     */
    function setKey(bytes32 key, bytes32 value) external;

    /******************************************************************************************************************\
    |                                               View/Pure Functions                                                |
    \******************************************************************************************************************/

    /**
     * @notice Returns the value of `key`.
     * @param  key Some key.
     * @return Some value.
     */
    function get(bytes32 key) external view returns (bytes32);

    /**
     * @notice Returns the values of `keys` respectively.
     * @param  keys Some keys.
     * @return Some values.
     */
    function get(bytes32[] calldata keys) external view returns (bytes32[] memory);

    /**
     * @notice Returns whether `list` contains `account`.
     * @param  list    The key for some list.
     * @param  account The address of some account.
     * @return Whether `list` contains `account`.
     */
    function listContains(bytes32 list, address account) external view returns (bool);

    /**
     * @notice Returns whether `list` contains all specified accounts.
     * @param  list     The key for some list.
     * @param  accounts An array of addressed of some accounts.
     * @return Whether `list` contains all specified accounts.
     */
    function listContains(bytes32 list, address[] calldata accounts) external view returns (bool);

    /// @notice Returns the address of the Emergency Governor.
    function emergencyGovernor() external view returns (address);

    /// @notice Returns the address of the Emergency Governor Deployer.
    function emergencyGovernorDeployer() external view returns (address);

    /// @notice Returns the address of the Power Token.
    function powerToken() external view returns (address);

    /// @notice Returns the address of the Power Token Deployer.
    function powerTokenDeployer() external view returns (address);

    /// @notice Returns the address of the Standard Governor.
    function standardGovernor() external view returns (address);

    /// @notice Returns the address of the Standard Governor Deployer.
    function standardGovernorDeployer() external view returns (address);

    /// @notice Returns the address of the Vault.
    function vault() external view returns (address);

    /// @notice Returns the address of the Zero Governor.
    function zeroGovernor() external view returns (address);

    /// @notice Returns the address of the Zero Token.
    function zeroToken() external view returns (address);
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

/// @title Minimal OpenZeppelin-style, Tally-compatible governor.
interface IGovernor is IERC6372, IERC712 {
    /**
     * @notice Proposal state.
     * @param  Pending   The proposal has been created, but the vote has not started yet.
     * @param  Active    The proposal is currently in the voting period.
     * @param  Canceled  The proposal has been canceled.
     * @param  Defeated  The proposal has been defeated.
     * @param  Succeeded The proposal has succeeded.
     * @param  Queued    The proposal has been queued.
     * @param  Expired   The proposal has expired.
     * @param  Executed  The proposal has been executed.
     */
    enum ProposalState {
        Pending,
        Active,
        Canceled, // never used by TTG.
        Defeated,
        Succeeded,
        Queued, // never used by TTG.
        Expired,
        Executed
    }

    /******************************************************************************************************************\
    |                                                      Events                                                      |
    \******************************************************************************************************************/

    /**
     * @notice Emitted when a proposal has been created.
     * @param  proposalId  The unique identifier for the proposal.
     * @param  proposer    The address of the account that created the proposal.
     * @param  targets     An array of addresses that will be called upon the execution.
     * @param  values      An array of ETH amounts that will be sent to each respective target upon execution.
     * @param  signatures  Empty string array required to be compatible with OZ governor contract.
     * @param  callDatas   An array of call data used to call each respective target upon execution.
     * @param  voteStart   The first clock value when voting on the proposal is allowed.
     * @param  voteEnd     The last clock value when voting on the proposal is allowed.
     * @param  description The string of the description of the proposal.
     */
    event ProposalCreated(
        uint256 proposalId,
        address proposer,
        address[] targets,
        uint256[] values,
        string[] signatures,
        bytes[] callDatas,
        uint256 voteStart,
        uint256 voteEnd,
        string description
    );

    /**
     * @notice Emitted when a proposal has been executed.
     * @param  proposalId The unique identifier for the proposal.
     */
    event ProposalExecuted(uint256 proposalId);

    /**
     * @notice Emitted when a vote for a proposal with id `proposalId` has been cast by `voter`.
     * @param  voter      The address of the account that has casted their vote.
     * @param  proposalId The unique identifier for the proposal.
     * @param  support    The type of support that has been cast for the proposal.
     * @param  weight     The number of votes cast.
     * @param  reason     The string of the reason `voter` has cast their vote, if any.
     */
    event VoteCast(address indexed voter, uint256 proposalId, uint8 support, uint256 weight, string reason);

    /******************************************************************************************************************\
    |                                              Interactive Functions                                               |
    \******************************************************************************************************************/

    /**
     * @notice Allows the caller to cast a vote on a proposal with id `proposalId`.
     * @param  proposalId The unique identifier for the proposal.
     * @param  support    The type of support to cast for the proposal.
     * @return weight     The number of votes cast.
     */
    function castVote(uint256 proposalId, uint8 support) external returns (uint256 weight);

    /**
     * @notice Allows a signer to cast a vote on a proposal with id `proposalId` via an ECDSA secp256k1 signature.
     * @param  proposalId The unique identifier for the proposal.
     * @param  support    The type of support to cast for the proposal.
     * @param  v          An ECDSA secp256k1 signature parameter.
     * @param  r          An ECDSA secp256k1 signature parameter.
     * @param  s          An ECDSA secp256k1 signature parameter.
     * @return weight     The number of votes cast.
     */
    function castVoteBySig(
        uint256 proposalId,
        uint8 support,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (uint256 weight);

    /**
     * @notice Allows `voter` to cast a vote on a proposal with id `proposalId` via an arbitrary signature.
     * @param  voter      The address of the account that casting their vote, and purported the have signed.
     * @param  proposalId The unique identifier for the proposal.
     * @param  support    The type of support to cast for the proposal.
     * @param  signature  An arbitrary signature.
     * @return weight     The number of votes cast.
     */
    function castVoteBySig(
        address voter,
        uint256 proposalId,
        uint8 support,
        bytes memory signature
    ) external returns (uint256 weight);

    /**
     * @notice Allows the caller to cast a vote on a proposal with id `proposalId`.
     * @param  proposalId The unique identifier for the proposal.
     * @param  support    The type of support to cast for the proposal.
     * @param  reason     The string of the reason the caller has cast their vote, if any.
     * @return weight     The number of votes cast.
     */
    function castVoteWithReason(
        uint256 proposalId,
        uint8 support,
        string calldata reason
    ) external returns (uint256 weight);

    /**
     * @notice Allows the caller to execute a proposal.
     * @param  targets         An array of addresses that will be called upon the execution.
     * @param  values          An array of ETH amounts that will be sent to each respective target upon execution.
     * @param  callDatas       An array of call data used to call each respective target upon execution.
     * @param  descriptionHash The hash of the string of the description of the proposal.
     * @return proposalId      The unique identifier for the proposal.
     */
    function execute(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory callDatas,
        bytes32 descriptionHash
    ) external payable returns (uint256 proposalId);

    /**
     * @notice Allows the caller to create a proposal.
     * @param  targets     An array of addresses that will be called upon the execution.
     * @param  values      An array of ETH amounts that will be sent to each respective target upon execution.
     * @param  callDatas   An array of call data used to call each respective target upon execution.
     * @param  description The string of the description of the proposal.
     * @return proposalId  The unique identifier for the proposal.
     */
    function propose(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory callDatas,
        string memory description
    ) external returns (uint256 proposalId);

    /******************************************************************************************************************\
    |                                               View/Pure Functions                                                |
    \******************************************************************************************************************/

    /**
     * @notice module:voting
     * @dev    A description of the possible "support" values for castVote and the way these votes are counted, meant to
     *         be consumed by UIs to show correct vote options and interpret the results. The string is a URL-encoded
     *         sequence of key-value pairs that each describe one aspect, for example `support=for,against&quorum=for`.
     *         The string can be decoded by the standard URLSearchParams JavaScript class.
     */
    function COUNTING_MODE() external view returns (string memory);

    /**
     * @notice Returns the voting power of `account` at clock value `timepoint`.
     * @param  account   The address of the account with voting power.
     * @param  timepoint The point in time, according to the clock mode the contract is operating on.
     * @return The voting power of `account` at `timepoint`.
     */
    function getVotes(address account, uint256 timepoint) external view returns (uint256);

    /**
     * @notice Returns the unique identifier for the proposal if it were created at this exact moment.
     * @param  targets         An array of addresses that will be called upon the execution.
     * @param  values          An array of ETH amounts that will be sent to each respective target upon execution.
     * @param  callDatas       An array of call data used to call each respective target upon execution.
     * @param  descriptionHash The hash of the string of the description of the proposal.
     * @return The unique identifier for the proposal.
     */
    function hashProposal(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory callDatas,
        bytes32 descriptionHash
    ) external view returns (uint256);

    /**
     * @notice Returns whether `account` has voted on the proposal with identifier `proposalId`.
     * @param  proposalId The unique identifier for the proposal.
     * @param  account    The address of some account.
     * @return Whether `account` has already voted on the proposal.
     */
    function hasVoted(uint256 proposalId, address account) external view returns (bool);

    /// @notice Returns the name of the contract.
    function name() external view returns (string memory);

    /**
     * @notice Returns the last clock value when voting on the proposal with identifier `proposalId` is allowed.
     * @param  proposalId The unique identifier for the proposal.
     * @return The last clock value when voting on the proposal is allowed.
     */
    function proposalDeadline(uint256 proposalId) external view returns (uint256);

    /**
     * @notice Returns the account that created the proposal with identifier `proposalId`.
     * @param  proposalId The unique identifier for the proposal.
     * @return The address of the account that created the proposal.
     */
    function proposalProposer(uint256 proposalId) external view returns (address);

    /**
     * @notice Returns the clock value used to retrieve voting power to vote on proposal with identifier `proposalId`.
     * @param  proposalId The unique identifier for the proposal.
     * @return The clock value used to retrieve voting power.
     */
    function proposalSnapshot(uint256 proposalId) external view returns (uint256);

    /// @notice Returns the required voting power an account needs to create a proposal.
    function proposalThreshold() external view returns (uint256);

    /// @notice Returns the minimum number of eligible (COUNTING_MODE) votes for a proposal to succeed.
    function quorum() external view returns (uint256);

    /**
     * @notice Returns the minimum number of eligible (COUNTING_MODE) votes for a proposal to succeed at `timepoint`.
     * @param  timepoint The point in time, according to the clock mode the contract is operating on.
     * @return The quorum value at `timepoint`.
     */
    function quorum(uint256 timepoint) external view returns (uint256);

    /**
     * @notice Returns the state of a proposal with identifier `proposalId`.
     * @param  proposalId The unique identifier for the proposal.
     * @return The state of the proposal.
     */
    function state(uint256 proposalId) external view returns (ProposalState);

    /// @notice Returns the number of clock values that must elapse before voting begins for a newly created proposal.
    function votingDelay() external view returns (uint256);

    /// @notice Returns the number of clock values between the vote start and vote end.
    function votingPeriod() external view returns (uint256);

    /// @notice Returns the EIP712 typehash used in the encoding of the digest for the castVoteBySig function.
    function BALLOT_TYPEHASH() external pure returns (bytes32);
}

/// @title Extension for Governor with specialized strict proposal parameters, vote batching, and an epoch clock.
interface IBatchGovernor is IGovernor {
    /******************************************************************************************************************\
    |                                                      Enums                                                       |
    \******************************************************************************************************************/

    enum VoteType {
        No,
        Yes
    }

    /******************************************************************************************************************\
    |                                                      Errors                                                      |
    \******************************************************************************************************************/

    /// @notice Revert message when a voter is trying to vote on a proposal they already voted on.
    error AlreadyVoted();

    /**
     * @notice Revert message when execution of a proposal fails.
     * @param  data The revert data returned due to the failed execution.
     */
    error ExecutionFailed(bytes data);

    /// @notice Revert message when an invalid epoch is detected.
    error InvalidEpoch();

    /// @notice Revert message when a proposal's call data is not specifically supported.
    error InvalidCallData();

    /// @notice Revert message when a proposal's call data array is not of length 1.
    error InvalidCallDatasLength();

    /// @notice Revert message when a proposal target is no this governor itself.
    error InvalidTarget();

    /// @notice Revert message when a proposal's targets array is not of length 1.
    error InvalidTargetsLength();

    /// @notice Revert message when a proposal value is not 0 ETH.
    error InvalidValue();

    /// @notice Revert message when a proposal's values array is not of length 1.
    error InvalidValuesLength();

    /// @notice Revert message when the vote token specified in the constructor is address(0).
    error InvalidVoteTokenAddress();

    /// @notice Revert message when the caller of a governance-controlled function is not this governor itself.
    error NotSelf();

    /// @notice Revert message when the proposal information provided cannot be executed.
    error ProposalCannotBeExecuted();

    /// @notice Revert message when the proposal does not exist.
    error ProposalDoesNotExist();

    /// @notice Revert message when the proposal already exists.
    error ProposalExists();

    /**
     * @notice Revert message when voting on a proposal that is not in an active state (i.e. not collecting votes).
     * @param  state The current state of the proposal.
     */
    error ProposalNotActive(ProposalState state);

    /******************************************************************************************************************\
    |                                              Interactive Functions                                               |
    \******************************************************************************************************************/

    /**
     * @notice Allows the caller to cast votes on multiple proposals.
     * @param  proposalIds An array of unique identifiers for the proposals.
     * @param  support     An array of the type of support that to cast for each respective proposal.
     * @return weight      The number of votes cast for each proposal (the same for all of them).
     */
    function castVotes(uint256[] calldata proposalIds, uint8[] calldata support) external returns (uint256 weight);

    /**
     * @notice Allows a signer to cast votes on multiple proposals via an ECDSA secp256k1 signature.
     * @param  proposalIds An array of unique identifiers for the proposals.
     * @param  support     An array of the type of support that to cast for each respective proposal.
     * @param  v           An ECDSA secp256k1 signature parameter.
     * @param  r           An ECDSA secp256k1 signature parameter.
     * @param  s           An ECDSA secp256k1 signature parameter.
     * @return weight      The number of votes cast for each proposal (the same for all of them).
     */
    function castVotesBySig(
        uint256[] calldata proposalIds,
        uint8[] calldata support,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (uint256 weight);

    /**
     * @notice Allows a signer to cast votes on multiple proposals via an arbitrary signature.
     * @param  proposalIds An array of unique identifiers for the proposals.
     * @param  support     An array of the type of support that to cast for each respective proposal.
     * @param  signature   An arbitrary signature
     * @return weight      The number of votes cast for each proposal (the same for all of them).
     */
    function castVotesBySig(
        address voter,
        uint256[] calldata proposalIds,
        uint8[] calldata support,
        bytes memory signature
    ) external returns (uint256 weight);

    /******************************************************************************************************************\
    |                                               View/Pure Functions                                                |
    \******************************************************************************************************************/

    /**
     * @notice Returns the digest to be signed, via EIP-712, given an internal digest (i.e. hash struct).
     * @param  proposalId The unique identifier of a proposal being voted on.
     * @param  support    The type of support to cast for the proposal.
     * @return The digest to be signed.
     */
    function getBallotDigest(uint256 proposalId, uint8 support) external view returns (bytes32);

    /**
     * @notice Returns the digest to be signed, via EIP-712, given an internal digest (i.e. hash struct).
     * @param  proposalIds The unique identifiers of an array of proposals being voted on.
     * @param  support     The type of support to cast for each proposal.
     * @return The digest to be signed.
     */
    function getBallotsDigest(uint256[] calldata proposalIds, uint8[] calldata support) external view returns (bytes32);

    /**
     * @notice Returns the unique identifier for the proposal if it were created at this exact moment.
     * @param  callData The single call data used to call this governor upon execution of a proposal.
     * @return The unique identifier for the proposal.
     */
    function hashProposal(bytes memory callData) external view returns (uint256);

    /// @notice Returns the EIP-5805 token contact used for determine voting power and total supplies.
    function voteToken() external view returns (address);

    /// @notice Returns the EIP712 typehash used in the encoding of the digest for the castVotesBySig function.
    function BALLOTS_TYPEHASH() external pure returns (bytes32);

    /// @notice Returns the value used as 100%, to be used to correctly ascertain the threshold ratio.
    function ONE() external pure returns (uint256);
}

/// @title Extension for BatchGovernor with a threshold ratio used to determine quorum and yes-threshold requirements.
interface IThresholdGovernor is IBatchGovernor {
    /******************************************************************************************************************\
    |                                                      Events                                                      |
    \******************************************************************************************************************/

    /**
     * @notice Emitted when the threshold ratio is set.
     * @param  thresholdRatio The new threshold ratio.
     */
    event ThresholdRatioSet(uint16 thresholdRatio);

    /******************************************************************************************************************\
    |                                                      Errors                                                      |
    \******************************************************************************************************************/

    /// @notice Revert message when trying to set the threshold ratio above 100% or below 2.71%.
    error InvalidThresholdRatio(uint256 thresholdRatio, uint256 minThresholdRatio, uint256 maxThresholdRatio);

    /******************************************************************************************************************\
    |                                               View/Pure Functions                                                |
    \******************************************************************************************************************/

    /**
     * @notice Returns all data of a proposal with identifier `proposalId`.
     * @param  proposalId     The unique identifier for the proposal.
     * @return voteStart      The first clock value when voting on the proposal is allowed.
     * @return voteEnd        The last clock value when voting on the proposal is allowed.
     * @return state          The state of the proposal.
     * @return noVotes        The amount of votes cast against the proposal.
     * @return yesVotes       The amount of votes cast for the proposal.
     * @return proposer       The address of the account that created the proposal.
     * @return thresholdRatio The threshold ratio to be applied to determine the threshold/quorum for the proposal.
     */
    function getProposal(
        uint256 proposalId
    )
        external
        view
        returns (
            uint48 voteStart,
            uint48 voteEnd,
            ProposalState state,
            uint256 noVotes,
            uint256 yesVotes,
            address proposer,
            uint16 thresholdRatio
        );

    /// @notice Returns the threshold ratio to be applied to determine the threshold/quorum for a proposal.
    function thresholdRatio() external view returns (uint16);
}

/// @title An instance of a ThresholdGovernor with a unique and limited set of possible proposals.
interface IZeroGovernor is IThresholdGovernor {
    /******************************************************************************************************************\
    |                                                      Events                                                      |
    \******************************************************************************************************************/

    /**
     * @notice Emitted upon a Reset, resulting in a new Standard Governor, Emergency Governor, and Power Token.
     * @param  bootstrapToken    The address of token (Zero Token or old Power Token), that bootstraps the reset.
     * @param  standardGovernor  The address of the new Standard Governor.
     * @param  emergencyGovernor The address of the new Emergency Governor.
     * @param  powerToken        The address of the new Power Token.
     */
    event ResetExecuted(
        address indexed bootstrapToken,
        address standardGovernor,
        address emergencyGovernor,
        address powerToken
    );

    /******************************************************************************************************************\
    |                                                      Errors                                                      |
    \******************************************************************************************************************/

    /// @notice Revert message when the Cash Token specified is not in the allowed set.
    error InvalidCashToken();

    /// @notice Revert message when the Cash Token specified in the constructor is address(0).
    error InvalidCashTokenAddress();

    /// @notice Revert message when the Emergency Governor Deployer specified in the constructor is address(0).
    error InvalidEmergencyGovernorDeployerAddress();

    /// @notice Revert message when the Power Token Deployer specified in the constructor is address(0).
    error InvalidPowerTokenDeployerAddress();

    /// @notice Revert message when the Standard Governor Deployer specified in the constructor is address(0).
    error InvalidStandardGovernorDeployerAddress();

    /// @notice Revert message when the set of allowed cash tokens specified in the constructor is empty.
    error NoAllowedCashTokens();

    /**
     * @notice Revert message when the address of the deployed Poker Token differs fro what was expected.
     * @param  expected The expected address of the deployed Poker Token.
     * @param  deployed The actual address of the deployed Poker Token.
     */
    error UnexpectedPowerTokenDeployed(address expected, address deployed);

    /**
     * @notice Revert message when the address of the deployed Standard Governor differs fro what was expected.
     * @param  expected The expected address of the deployed Standard Governor.
     * @param  deployed The actual address of the deployed Standard Governor.
     */
    error UnexpectedStandardGovernorDeployed(address expected, address deployed);

    /******************************************************************************************************************\
    |                                                Proposal Functions                                                |
    \******************************************************************************************************************/

    /**
     * @notice One of the valid proposals. Reset the Standard Governor, Emergency Governor, and Power Token to the
     *         Power Token holders. This would be used by Zero Token holders in the event that inflation is soon to
     *         result in Power Token overflowing, and/or there is a loss of faith in the state of either the Standard
     *         Governor or Emergency Governor.
     */
    function resetToPowerHolders() external;

    /**
     * @notice One of the valid proposals. Reset the Standard Governor, Emergency Governor, and Power Token to the
     *         ZeroToken holders. This would be used by Zero Token holders if they no longer have faith in the current
     *         set of PowerToken holders and/or the state of either the Standard Governor or Emergency Governor.
     */
    function resetToZeroHolders() external;

    /**
     * @notice One of the valid proposals. Sets the Cash Token of the system.
     * @param  newCashToken   The address of the new cash token.
     * @param  newProposalFee The amount of cash token required onwards to create Standard Governor proposals.
     */
    function setCashToken(address newCashToken, uint256 newProposalFee) external;

    /**
     * @notice One of the valid proposals. Sets the threshold ratio for Emergency Governor proposals.
     * @param  newThresholdRatio The new threshold ratio.
     */
    function setEmergencyProposalThresholdRatio(uint16 newThresholdRatio) external;

    /**
     * @notice One of the valid proposals. Sets the threshold ratio for this governor's proposals.
     * @param  newThresholdRatio The new threshold ratio.
     */
    function setZeroProposalThresholdRatio(uint16 newThresholdRatio) external;

    /******************************************************************************************************************\
    |                                               View/Pure Functions                                                |
    \******************************************************************************************************************/

    /**
     * @notice Returns whether `token` is an allowed Cash Token of the system, as a parameter in setCashToken proposal.
     * @param  token The address of some token.
     * @return Whether `token` is an allowed Cash Token.
     */
    function isAllowedCashToken(address token) external view returns (bool);

    /// @notice Returns the address of the Emergency Governor.
    function emergencyGovernor() external view returns (address);

    /// @notice Returns the address of the Emergency Governor Deployer.
    function emergencyGovernorDeployer() external view returns (address);

    /// @notice Returns the address of the Power Token Deployer.
    function powerTokenDeployer() external view returns (address);

    /// @notice Returns the address of the Standard Governor.
    function standardGovernor() external view returns (address);

    /// @notice Returns the address of the Standard Governor Deployer.
    function standardGovernorDeployer() external view returns (address);
}

/// @title A book of record of SPOG-specific contracts and arbitrary key-value pairs and lists.
contract Registrar is IRegistrar {
    /// @inheritdoc IRegistrar
    address public immutable emergencyGovernorDeployer;

    /// @inheritdoc IRegistrar
    address public immutable powerTokenDeployer;

    /// @inheritdoc IRegistrar
    address public immutable standardGovernorDeployer;

    /// @inheritdoc IRegistrar
    address public immutable vault;

    /// @inheritdoc IRegistrar
    address public immutable zeroGovernor;

    /// @inheritdoc IRegistrar
    address public immutable zeroToken;

    /// @notice A mapping of keys to values.
    mapping(bytes32 key => bytes32 value) internal _valueAt;

    /// @notice Revert if the caller is not the Standard Governor nor the Emergency Governor.
    modifier onlyStandardOrEmergencyGovernor() {
        _revertIfNotStandardOrEmergencyGovernor();
        _;
    }

    /**
     * @notice Constructs a new Registrar contract.
     * @param  zeroGovernor_ The address of the ZeroGovernor contract.
     */
    constructor(address zeroGovernor_) {
        if ((zeroGovernor = zeroGovernor_) == address(0)) revert InvalidZeroGovernorAddress();

        IZeroGovernor zeroGovernorInstance_ = IZeroGovernor(zeroGovernor_);

        if ((emergencyGovernorDeployer = zeroGovernorInstance_.emergencyGovernorDeployer()) == address(0))
            revert InvalidEmergencyGovernorDeployerAddress();

        if ((powerTokenDeployer = zeroGovernorInstance_.powerTokenDeployer()) == address(0))
            revert InvalidPowerTokenDeployerAddress();

        address standardGovernorDeployer_ = standardGovernorDeployer = zeroGovernorInstance_.standardGovernorDeployer();

        if (standardGovernorDeployer_ == address(0)) revert InvalidStandardGovernorDeployerAddress();

        if ((zeroToken = zeroGovernorInstance_.voteToken()) == address(0)) revert InvalidVoteTokenAddress();

        if ((vault = IStandardGovernorDeployer(standardGovernorDeployer_).vault()) == address(0))
            revert InvalidVaultAddress();
    }

    /******************************************************************************************************************\
    |                                      External/Public Interactive Functions                                       |
    \******************************************************************************************************************/

    /// @inheritdoc IRegistrar
    function addToList(bytes32 list_, address account_) external onlyStandardOrEmergencyGovernor {
        _valueAt[_getIsInListKey(list_, account_)] = bytes32(uint256(1));

        emit AddressAddedToList(list_, account_);
    }

    /// @inheritdoc IRegistrar
    function removeFromList(bytes32 list_, address account_) external onlyStandardOrEmergencyGovernor {
        delete _valueAt[_getIsInListKey(list_, account_)];

        emit AddressRemovedFromList(list_, account_);
    }

    /// @inheritdoc IRegistrar
    function setKey(bytes32 key_, bytes32 value_) external onlyStandardOrEmergencyGovernor {
        emit KeySet(key_, _valueAt[_getValueKey(key_)] = value_);
    }

    /******************************************************************************************************************\
    |                                       External/Public View/Pure Functions                                        |
    \******************************************************************************************************************/

    /// @inheritdoc IRegistrar
    function get(bytes32 key_) external view returns (bytes32) {
        return _valueAt[_getValueKey(key_)];
    }

    /// @inheritdoc IRegistrar
    function get(bytes32[] calldata keys_) external view returns (bytes32[] memory values_) {
        values_ = new bytes32[](keys_.length);

        for (uint256 index_; index_ < keys_.length; ++index_) {
            values_[index_] = _valueAt[_getValueKey(keys_[index_])];
        }
    }

    /// @inheritdoc IRegistrar
    function listContains(bytes32 list_, address account_) external view returns (bool) {
        return _valueAt[_getIsInListKey(list_, account_)] == bytes32(uint256(1));
    }

    /// @inheritdoc IRegistrar
    function listContains(bytes32 list_, address[] calldata accounts_) external view returns (bool) {
        for (uint256 index_; index_ < accounts_.length; ++index_) {
            if (_valueAt[_getIsInListKey(list_, accounts_[index_])] != bytes32(uint256(1))) return false;
        }

        return true;
    }

    /// @inheritdoc IRegistrar
    function powerToken() external view returns (address) {
        return IPowerTokenDeployer(powerTokenDeployer).lastDeploy();
    }

    /// @inheritdoc IRegistrar
    function emergencyGovernor() public view returns (address) {
        return IEmergencyGovernorDeployer(emergencyGovernorDeployer).lastDeploy();
    }

    /// @inheritdoc IRegistrar
    function standardGovernor() public view returns (address) {
        return IStandardGovernorDeployer(standardGovernorDeployer).lastDeploy();
    }

    /******************************************************************************************************************\
    |                                          Internal View/Pure Functions                                            |
    \******************************************************************************************************************/

    /// @dev Reverts if the caller is not the Standard Governor nor the Emergency Governor.
    function _revertIfNotStandardOrEmergencyGovernor() internal view {
        if (msg.sender != standardGovernor() && msg.sender != emergencyGovernor()) {
            revert NotStandardOrEmergencyGovernor();
        }
    }

    /**
     * @dev    Returns the key used to store the value of `key_`.
     * @param  key_ The key of the value.
     * @return The key used to store the value of `key_`.
     */
    function _getValueKey(bytes32 key_) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("VALUE", key_));
    }

    /**
     * @dev    Returns the key used to store whether `account_` is in `list_`.
     * @param  list_    The list of addresses.
     * @param  account_ The address of the account.
     * @return The key used to store whether `account_` is in `list_`.
     */
    function _getIsInListKey(bytes32 list_, address account_) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("IN_LIST", list_, account_));
    }
}


// SPDX-License-Identifier: MIT

pragma solidity 0.8.26;

import {LendingHookV4} from "./LendingHookV4.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/*//////////////////////////////////////////////////////////////
                              lo0p
                    web · https://lo0p.io
                    x   · https://x.com/lo0pio
                    tg  · https://t.me/lo0pio
//////////////////////////////////////////////////////////////*/
/// @title  LendingHookV4Factory — permissionless deployer for lo0p V4 hooks
/// @notice One hook per token. Anyone can call `deploy()` to register a market
///         for any ERC20. The factory atomically CREATE2-deploys the hook AND
///         initializes its V4 pool in the same tx — eliminating the front-run
///         window between deploy and init.
///
///         The factory does NOT embed `LendingHookV4`'s creation code in its
///         runtime bytecode (EIP-170 24 KB limit would be exceeded). Instead
///         the caller passes the init code as calldata, and the factory
///         validates that:
///           1. The CREATE2 address ends in the V4 permission bits 0x3ACC.
///           2. The init code's creation-code prefix matches the canonical
///              `expectedCreationCodeHash` set at factory deploy time.
///           3. The init code's ctor args encode the same `token` passed to
///              `deploy()`.
///           4. The deployed hook address is not the token address itself
///              (salt-mining collision defense).
///
///         These four checks ensure that ONLY the canonical, audited
///         `LendingHookV4` bytecode can be registered — even though deployment
///         itself is permissionless. A caller cannot register arbitrary code
///         or substitute a different token mid-deploy.
///
///         ─── Risks of permissionless deploys ───
///         · Token squatting: an attacker may pre-register a hook for a
///           popular token (e.g. USDC) with a bad `sqrtPriceX96`. The first
///           hook to register wins the `hookForToken` slot forever.
///         · Frontend / indexers MUST maintain a curated allowlist of hooks
///           they trust — the factory itself enforces no quality bar on
///           token choice or initial price (beyond `MIN_SQRT_PRICE` and the
///           `< 2^126` upper bound checked inside `initializePool`).
///         · Bad-token risk: anyone can register a hook for rebasing /
///           ERC-777 / fee-on-transfer / scam tokens. These break accounting
///           silently. Users should only interact via curated frontends.
///
///         Workflow:
///           1. Off-chain, build initCode = LendingHookV4.creationCode || abi.encode(token).
///           2. Mine a `salt` whose CREATE2 address has lower-14 bits == 0x3ACC.
///           3. Call `deploy(initCode, salt, token, sqrtPriceX96)`.
///           4. Factory: CREATE2-deploys, checks bits + creationCode hash +
///              encoded token + non-collision, calls `initializePool(...)`,
///              writes registry, emits `HookDeployed`.
contract LendingHookV4Factory {
    // ─── Constants ──────────────────────────────────────────────────────────
    /// @notice V4 hook permission bits required by `LendingHookV4`. The lower
    ///         14 bits of the hook's address MUST equal this exact value.
    uint160 public constant HOOK_PERMISSION_BITS = 0x3ACC;
    uint160 public constant HOOK_PERMISSION_MASK = 0x3FFF; // lower 14 bits

    /// @notice Ctor arg byte length appended to creationCode. V4 takes a
    ///         single `IERC20` (address) → abi-encoded as 32 bytes.
    uint256 public constant CTOR_ARGS_LEN = 32;

    // ─── Immutables ─────────────────────────────────────────────────────────
    /// @notice keccak256 of the canonical `LendingHookV4.creationCode`
    ///         (without ctor args). Every deploy's initCode prefix is hashed
    ///         and compared to this value — defends against callers submitting
    ///         arbitrary bytecode.
    bytes32 public immutable expectedCreationCodeHash;

    // ─── State ──────────────────────────────────────────────────────────────
    /// @notice Canonical hook per token. Enforced one-to-one. First deployer
    ///         to register a token wins the slot permanently.
    mapping(address token => address hook) public hookForToken;

    /// @notice Total number of hooks deployed by this factory. Monotonic,
    ///         doubles as the next index to write into `hookAtIndex`.
    uint256 public totalHooks;

    /// @notice Append-only indexed registry of every hook ever deployed.
    ///         `hookAtIndex[0..totalHooks-1]` enumerates deploy order.
    mapping(uint256 index => address hook) public hookAtIndex;

    // ─── Events ─────────────────────────────────────────────────────────────
    event HookDeployed(
        address indexed token,
        address indexed hook,
        address indexed deployer,
        uint160 sqrtPriceX96,
        bytes32 salt,
        uint256 index
    );

    // ─── Errors ─────────────────────────────────────────────────────────────
    error ZeroAddress();
    error InitCodeTooShort();
    error DeployFailed();
    error InvalidPermissionBits(address deployed);
    error WrongCreationCode(bytes32 actual);
    error TokenMismatch(address inInitCode, address inArgs);
    error TokenAlreadyHasHook(address token, address existingHook);
    error TokenHookCollision(address addr);

    // ─── Constructor ────────────────────────────────────────────────────────
    /// @param expectedCreationCodeHash_  keccak256 of LendingHookV4's
    ///                                   compiled `creationCode` (without
    ///                                   ctor args). Compute off-chain from
    ///                                   the artifact.
    constructor(bytes32 expectedCreationCodeHash_) {
        if (expectedCreationCodeHash_ == bytes32(0)) revert ZeroAddress();
        expectedCreationCodeHash = expectedCreationCodeHash_;
    }

    // ─── Deploy ─────────────────────────────────────────────────────────────
    /// @notice Atomically CREATE2-deploy a `LendingHookV4` and initialize its
    ///         V4 pool. Permissionless — anyone can call. The 4-layer init
    ///         code validation (codehash + ctor args + permission bits +
    ///         non-collision) ensures only the canonical hook bytecode can
    ///         be registered.
    /// @param  initCode      LendingHookV4.creationCode || abi.encode(token)
    /// @param  salt          CREATE2 salt — must produce an address whose
    ///                       lower 14 bits == 0x3ACC. Mine off-chain.
    /// @param  token         Underlying ERC20 — recorded in the registry.
    ///                       MUST match the address encoded into `initCode`.
    /// @param  sqrtPriceX96  Initial V4 pool price. Must be in the range
    ///                       enforced by `LendingHookV4.initializePool`.
    /// @return hook          Address of the deployed hook.
    function deploy(
        bytes calldata initCode,
        bytes32 salt,
        IERC20 token,
        uint160 sqrtPriceX96
    ) external returns (address hook) {
        if (address(token) == address(0)) revert ZeroAddress();
        if (initCode.length <= CTOR_ARGS_LEN) revert InitCodeTooShort();
        address existing = hookForToken[address(token)];
        if (existing != address(0)) revert TokenAlreadyHasHook(address(token), existing);

        // Verify the init code's creation-code prefix matches the canonical
        // LendingHookV4 — defense against callers submitting arbitrary code.
        uint256 ccLen = initCode.length - CTOR_ARGS_LEN;
        bytes32 creationHash;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            calldatacopy(ptr, initCode.offset, ccLen)
            creationHash := keccak256(ptr, ccLen)
        }
        if (creationHash != expectedCreationCodeHash) revert WrongCreationCode(creationHash);

        // Verify the token encoded into ctor args matches the registry param.
        address encodedToken;
        assembly ("memory-safe") {
            encodedToken := calldataload(add(initCode.offset, ccLen))
        }
        if (encodedToken != address(token)) revert TokenMismatch(encodedToken, address(token));

        // CREATE2 deploy
        address deployed;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            calldatacopy(ptr, initCode.offset, initCode.length)
            deployed := create2(0, ptr, initCode.length, salt)
        }
        if (deployed == address(0)) revert DeployFailed();

        // Validate V4 permission bits in the address
        if (uint160(deployed) & HOOK_PERMISSION_MASK != HOOK_PERMISSION_BITS) {
            revert InvalidPermissionBits(deployed);
        }

        // Defense against the salt-mined collision where the predicted hook
        // address equals the token address — would make the hook reference
        // itself as the collateral token, bricking every operation.
        if (deployed == address(token)) revert TokenHookCollision(deployed);

        // Init pool atomically. Permissionless on V4 — this single tx forms
        // the entire window for picking the initial sqrtPriceX96.
        LendingHookV4(payable(deployed)).initializePool(sqrtPriceX96);

        // Registry — write to next free index, then bump counter
        uint256 idx = totalHooks;
        hookForToken[address(token)] = deployed;
        hookAtIndex[idx] = deployed;
        unchecked { totalHooks = idx + 1; }

        emit HookDeployed(address(token), deployed, msg.sender, sqrtPriceX96, salt, idx);
        return deployed;
    }

    // ─── Views ──────────────────────────────────────────────────────────────
    /// @notice Predict the address `deploy()` will produce for the given
    ///         init-code hash + salt. Use off-chain to mine salts until the
    ///         permission bits match.
    function predict(bytes32 initCodeHash_, bytes32 salt) external view returns (address) {
        bytes32 h = keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, initCodeHash_));
        return address(uint160(uint256(h)));
    }
}

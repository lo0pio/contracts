// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/*//////////////////////////////////////////////////////////////
                              lo0p
                    web · https://lo0p.io
                    x   · https://x.com/lo0pio
                    tg  · https://t.me/lo0pio
//////////////////////////////////////////////////////////////*/

import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {IUnlockCallback} from "@uniswap/v4-core/src/interfaces/callback/IUnlockCallback.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {Currency, CurrencyLibrary} from "@uniswap/v4-core/src/types/Currency.sol";
import {BalanceDelta} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary, toBeforeSwapDelta} from "@uniswap/v4-core/src/types/BeforeSwapDelta.sol";
import {ModifyLiquidityParams, SwapParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {TickMath} from "@uniswap/v4-core/src/libraries/TickMath.sol";
import {StateLibrary} from "@uniswap/v4-core/src/libraries/StateLibrary.sol";

import {LOOP} from "./LOOP.sol";
import {IFeeCollector} from "./interfaces/IFeeCollector.sol";
import {LDF} from "./libraries/LDF.sol";

/// @title  LendingHookV2 — V4-native multi-tick lending AMM
/// @notice The lo0p protocol redesigned around Uniswap V4 concentrated liquidity.
///         At init, the hook seeds the V4 pool with single-sided LOOP-only
///         positions across N discrete bands (each 30 ETH wide in pool-ETH
///         space). All buy/sell flows are pure V4 native — the hook only
///         intercepts to skim a 1% fee and enforce the same-block lockout.
///
///         The big change vs V1 is range-aware lending. When a user borrows,
///         the hook removes ETH-side liquidity from a SPECIFIC band (the band
///         containing the position's projected liquidation price). Liquidation
///         later sells the collateral via V4 swap and routes the ETH proceeds
///         BACK to that same band as fresh single-sided liquidity, leaving the
///         band stronger than before — no LOOP burn.
contract LendingHookV2 is IHooks, IUnlockCallback {
    using StateLibrary for IPoolManager;

    // ─── Constants ──────────────────────────────────────────────────────────
    uint256 public constant LTV_BPS                   = 4000;   // 40 %
    uint256 public constant ORIG_FEE_BPS              = 100;    // 1 %  of collateral value
    uint256 public constant SWAP_FEE_BPS              = 100;    // 1 %  on every swap → FeeCollector
    uint256 public constant LIQUIDATION_THRESHOLD_BPS = 15_000; // 150 %
    uint256 public constant LIQUIDATION_BOUNTY_BPS    = 100;    // 1 %  of debt
    uint256 public constant MAX_LIQUIDATION_BOUNTY    = 0.01 ether; // hard cap regardless of debt size
    uint256 public constant REPAY_COOLDOWN_BLOCKS     = 2;
    uint256 public constant MIN_COLLATERAL_VALUE      = 0.1 ether;
    uint256 public constant NUM_INITIAL_BANDS         = 100;    // covers realETH 0..3000

    // ─── Errors ─────────────────────────────────────────────────────────────
    error NotOwner();
    error NotPoolManager();
    error PoolAlreadyInitialized();
    error PoolNotInitializedErr();
    error UnauthorizedLP();
    error ZeroAddress();
    error Reentrancy();
    error InvalidAction();
    error EthTransferFailed();
    error TokenSupplyMismatch();
    error InvalidPoolKey();
    error FeeForwardFailed();
    error SwapInSameBlock();
    error CollateralBelowMin();
    error NoOpenPosition();
    error CooldownActive();
    error RepayAmountMismatch();
    error NotUnderwater();
    error TickFull();
    error BoundAboveSpot();
    error InvalidBoundTick();
    error SwapBlockedByLiquidation();
    error OneLiquidationPerBlock();
    error NotStarted();
    error AlreadyStarted();
    error BootstrapClosed();
    error SlippageExceeded();

    // ─── Immutables ─────────────────────────────────────────────────────────
    IPoolManager   public immutable poolManager;
    LOOP           public immutable loop;
    IFeeCollector  public immutable feeCollector;

    /// @notice Hook owner. Can call `initializePool`, `seedBands`, and
    ///         `renounceOwnership`. Not immutable so that ownership can be
    ///         permanently relinquished — once renounced (set to address(0))
    ///         no one can ever call onlyOwner functions again.
    address public owner;

    // ─── State ──────────────────────────────────────────────────────────────
    PoolKey public poolKey;
    bool    public poolInitialized;

    /// @notice Accounting per LDF band. `liquidity` mirrors the V4 LP position
    ///         the hook holds for that band; `borrowedETH` is the cumulative
    ///         ETH currently lent out of this band's reserves (released back
    ///         on repay/liquidation).
    struct TickBand {
        int24   v4TickLower;
        int24   v4TickUpper;
        uint128 liquidity;
        uint256 borrowedETH;
    }
    mapping(uint256 bandId => TickBand) public bands;

    /// @notice Per-(user, boundTick) position. Multi-position per user is
    ///         supported: each unique boundTick is a distinct position.
    struct Position {
        uint256 collateralLOOP;
        uint256 debtETH;
        uint64  openedAtBlock;
    }
    mapping(address user => mapping(uint256 boundBand => Position)) public positions;

    uint256 public totalOutstandingDebt;
    uint256 public totalCollateralLocked;

    /// @notice Same-block lockout for borrow/liquidate after a swap. Mirrors V1.
    uint64 public lastSwapBlock;
    uint64 public launchBlock;

    /// @notice Block number of the most recent liquidation. External (user)
    ///         swaps are blocked in any block that has had a liquidation —
    ///         closes the cross-pool buyback leg of the atomic-bundle attack.
    ///         Hook's own internal swap inside _handleLiquidate is identified
    ///         by `sender == address(this)` in beforeSwap and bypasses the check.
    uint64 public lastLiquidationBlock;

    /// @notice True after `start()` is called — gates public swaps so the
    ///         owner can perform `ownerBootstrapBuy` first (no front-run window).
    ///         Once set, never unset.
    bool public started;

    // ─── Events ─────────────────────────────────────────────────────────────
    event PoolReady(PoolId indexed id, uint256 totalSupplyDeployed, uint256 numBands);
    event BandSeeded(uint256 indexed bandId, int24 tickLower, int24 tickUpper, uint256 loopAmount, uint128 liquidity);
    event Swapped(address indexed origin, bool zeroForOne, uint256 amountIn, uint256 fee);
    event Borrowed(
        address indexed user, uint256 indexed boundBand,
        uint256 collateralLOOP, uint256 debtETH, uint256 netToUser, uint256 originationFee
    );
    event Repaid(address indexed user, uint256 indexed boundBand, uint256 amountETH, uint256 collateralReturned, bool full);
    event Liquidated(
        address indexed victim, address indexed liquidator, uint256 indexed boundBand,
        uint256 collateralLOOP, uint256 ethProceeds, uint256 bountyETH, uint256 toReplenish
    );
    event OwnerTransferred(address indexed previous, address indexed next);
    event BootstrapBuy(address indexed buyer, uint256 ethIn, uint256 loopOut);
    event ProtocolStarted(uint64 indexed atBlock);

    // ─── Modifiers ──────────────────────────────────────────────────────────
    uint256 private _locked = 1;
    modifier nonReentrant() {
        if (_locked != 1) revert Reentrancy();
        _locked = 2;
        _;
        _locked = 1;
    }
    modifier onlyOwner() { if (msg.sender != owner) revert NotOwner(); _; }
    modifier onlyPoolManager() { if (msg.sender != address(poolManager)) revert NotPoolManager(); _; }

    // ─── Constructor ────────────────────────────────────────────────────────
    constructor(
        IPoolManager poolManager_,
        LOOP loop_,
        IFeeCollector feeCollector_,
        address owner_
    ) {
        if (
            address(poolManager_) == address(0) || address(loop_) == address(0)
                || address(feeCollector_) == address(0) || owner_ == address(0)
        ) revert ZeroAddress();

        poolManager = poolManager_;
        loop = loop_;
        feeCollector = feeCollector_;
        owner = owner_;

        Hooks.validateHookPermissions(IHooks(address(this)), getHookPermissions());
        emit OwnerTransferred(address(0), owner_);
    }

    // ─── Hook permissions ───────────────────────────────────────────────────
    function getHookPermissions() public pure returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize:           true,
            afterInitialize:            true,
            beforeAddLiquidity:         true,   // 3rd-party LP guard
            afterAddLiquidity:          false,
            beforeRemoveLiquidity:      true,   // 3rd-party guard
            afterRemoveLiquidity:       false,
            beforeSwap:                 true,   // ETH fee on BUY input
            afterSwap:                  true,   // ETH fee on SELL output + record lastSwapBlock
            beforeDonate:               false,
            afterDonate:                false,
            beforeSwapReturnDelta:      true,   // returns BeforeSwapDelta to skim ETH on buys
            afterSwapReturnDelta:       true,   // returns int128 to skim ETH on sells
            afterAddLiquidityReturnDelta:    false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    // ─── Ownership ──────────────────────────────────────────────────────────

    /// @notice Permanently relinquish ownership. After this call, no further
    ///         onlyOwner functions can ever be called — the contract becomes
    ///         fully unmanaged. Intended to be called once after `start()` so
    ///         that public swaps are already open (otherwise the contract
    ///         would be permanently bricked with no way to start it).
    /// @dev    Irreversible. owner = address(0).
    function renounceOwnership() external onlyOwner {
        if (!started) revert NotStarted();
        emit OwnerTransferred(owner, address(0));
        owner = address(0);
    }

    // ─── Pool setup ─────────────────────────────────────────────────────────

    /// @notice Initialize the V4 pool. Must be called once by owner.
    ///         Pool starts at sqrtPrice corresponding to realETH = 0.
    function initializePool() external onlyOwner {
        if (poolInitialized) revert PoolAlreadyInitialized();
        if (loop.balanceOf(address(this)) != LDF.TOTAL_SUPPLY) revert TokenSupplyMismatch();

        PoolKey memory key = PoolKey({
            currency0: CurrencyLibrary.ADDRESS_ZERO, // native ETH
            currency1: Currency.wrap(address(loop)),
            fee:       0,                            // hook applies its own 1% fee
            tickSpacing: LDF.TICK_SPACING,
            hooks:     IHooks(address(this))
        });
        poolKey = key;

        // Initialise at band 0's tickUpper so currentTick is strictly above every
        // seeded band (positions are half-open: currentTick < tickUpper means
        // "in range", currentTick == tickUpper means "below"). This guarantees
        // every band is single-sided LOOP at seed time.
        (, int24 band0TickUpper) = LDF.bandToV4Ticks(0);
        uint160 initialSqrtPriceX96 = TickMath.getSqrtPriceAtTick(band0TickUpper);
        poolManager.initialize(key, initialSqrtPriceX96);
        poolInitialized = true;
        launchBlock = uint64(block.number);
    }

    /// @notice After initializePool, owner calls this in batches to seed each
    ///         LDF band with single-sided LOOP-only liquidity. May be called
    ///         multiple times (resumable if a single tx hits the gas ceiling).
    function seedBands(uint256 fromBand, uint256 toBand) external onlyOwner nonReentrant {
        if (!poolInitialized) revert PoolNotInitializedErr();
        require(toBand <= NUM_INITIAL_BANDS && fromBand < toBand, "BadRange");

        // Approve the PM to pull LOOP via settle
        loop.approve(address(poolManager), type(uint256).max);

        // Encode batch of band seeding actions for unlockCallback
        poolManager.unlock(abi.encode(Action.SEED_BANDS, abi.encode(fromBand, toBand)));
    }

    // ─── Bootstrap ──────────────────────────────────────────────────────────

    /// @notice Pre-launch buy executed by the owner before the public swap gate
    ///         is opened. Hook performs the swap internally (sender == self ⇒
    ///         beforeSwap bypasses the !started and lastLiquidationBlock checks)
    ///         so the owner gets ETH→LOOP at the pristine initial curve with no
    ///         front-running. The 1% SWAP_FEE_BPS still applies — it is skimmed
    ///         off the input ETH and routed to FeeCollector before the swap runs.
    /// @dev    May be called multiple times while `!started`. Each call extracts
    ///         LOOP into the owner's wallet (via PoolManager.take), so the
    ///         hook never holds the proceeds.
    /// @param  minLoopOut Slippage floor — the call reverts if the LOOP
    ///                    received is below this amount. Compute off-chain
    ///                    using the constant-product math on `msg.value × 99%`.
    /// @return loopOut    LOOP wei delivered to msg.sender.
    function ownerBootstrapBuy(uint128 minLoopOut)
        external
        payable
        onlyOwner
        nonReentrant
        returns (uint256 loopOut)
    {
        if (started) revert BootstrapClosed();
        if (!poolInitialized) revert PoolNotInitializedErr();
        require(msg.value > 0, "ZeroEth");

        // Skim 1% swap fee to FeeCollector — owner pays the same fee public
        // swappers will pay. The remaining 99% enters the curve.
        uint256 fee = (msg.value * SWAP_FEE_BPS) / 10000;
        uint256 swapAmount = msg.value - fee;
        if (fee > 0) {
            (bool ok, ) = address(feeCollector).call{value: fee}("");
            if (!ok) revert FeeForwardFailed();
        }

        bytes memory ret = poolManager.unlock(abi.encode(
            Action.OWNER_BUY,
            abi.encode(swapAmount, msg.sender)
        ));
        loopOut = abi.decode(ret, (uint256));
        if (loopOut < minLoopOut) revert SlippageExceeded();

        emit BootstrapBuy(msg.sender, msg.value, loopOut);
    }

    /// @notice Open public swaps. After this call, anyone can swap on the lo0p
    ///         pool through the Universal Router (or directly via the PM).
    ///         `ownerBootstrapBuy` becomes uncallable.
    ///         Idempotent (no-op if already started).
    function start() external onlyOwner {
        if (started) return;
        started = true;
        emit ProtocolStarted(uint64(block.number));
    }

    // ─── Hooks ──────────────────────────────────────────────────────────────

    function beforeInitialize(address, PoolKey calldata key, uint160)
        external
        view
        onlyPoolManager
        returns (bytes4)
    {
        if (Currency.unwrap(key.currency0) != address(0))   revert InvalidPoolKey();
        if (Currency.unwrap(key.currency1) != address(loop)) revert InvalidPoolKey();
        if (key.fee != 0)                                    revert InvalidPoolKey();
        if (key.tickSpacing != LDF.TICK_SPACING)             revert InvalidPoolKey();
        if (address(key.hooks) != address(this))             revert InvalidPoolKey();
        return IHooks.beforeInitialize.selector;
    }

    function afterInitialize(address, PoolKey calldata, uint160, int24)
        external
        pure
        returns (bytes4)
    {
        return IHooks.afterInitialize.selector;
    }

    function beforeAddLiquidity(address sender, PoolKey calldata, ModifyLiquidityParams calldata, bytes calldata)
        external
        view
        onlyPoolManager
        returns (bytes4)
    {
        // Only the hook itself may add liquidity (during seedBands or repay/liquidate refill)
        if (sender != address(this)) revert UnauthorizedLP();
        return IHooks.beforeAddLiquidity.selector;
    }

    function beforeRemoveLiquidity(address sender, PoolKey calldata, ModifyLiquidityParams calldata, bytes calldata)
        external
        view
        onlyPoolManager
        returns (bytes4)
    {
        if (sender != address(this)) revert UnauthorizedLP();
        return IHooks.beforeRemoveLiquidity.selector;
    }

    /// @notice Charges 1% ETH fee on BUY (zeroForOne=true, exact-input). Pulls
    ///         the fee from PoolManager's reserves via take() and forwards it
    ///         to FeeCollector. Returns a positive specified-side BeforeSwapDelta
    ///         so the caller's ETH input is increased by `fee` to refund PM.
    ///         SELL fees are taken in afterSwap (output is ETH there).
    function beforeSwap(address sender, PoolKey calldata key, SwapParams calldata params, bytes calldata)
        external
        onlyPoolManager
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        // Hook-internal swaps (liquidation, ownerBootstrapBuy) bypass every
        // gate. Identified by `sender == address(this)` because the hook is
        // the entity that called poolManager.swap inside its unlockCallback.
        if (sender == address(this)) {
            return (IHooks.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
        }
        // Public not opened yet — only owner bootstrap allowed (which bypasses
        // above via sender check). Closes the launch front-run window.
        if (!started) {
            revert NotStarted();
        }
        // Reject external swaps in any block that has had a liquidation.
        // Closes the cross-pool buyback leg of the atomic-bundle MEV attack:
        // attackers can't dump on a side pool, dump on lo0p via liquidations,
        // then buy back here at the crashed price within the same block.
        if (block.number == lastLiquidationBlock) {
            revert SwapBlockedByLiquidation();
        }
        // Only handle BUY direction here (ETH-in). SELL handled in afterSwap.
        if (!params.zeroForOne) {
            return (IHooks.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
        }
        // Exact-input only (negative amountSpecified).
        if (params.amountSpecified >= 0) {
            return (IHooks.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
        }

        uint256 amountIn = uint256(-params.amountSpecified);
        uint256 fee = (amountIn * SWAP_FEE_BPS) / 10000;
        if (fee == 0) {
            return (IHooks.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
        }

        // Forward fee directly to FeeCollector. PM has ETH reserves from other
        // pools / our LP — the call succeeds; the user's BeforeSwapDelta below
        // refunds PM's accounting by making the user pay `fee` more on input.
        poolManager.take(key.currency0, address(feeCollector), fee);

        return (
            IHooks.beforeSwap.selector,
            toBeforeSwapDelta(int128(int256(fee)), 0),
            0
        );
    }

    /// @notice Charges 1% ETH fee on SELL (zeroForOne=false, exact-input). Output
    ///         is ETH (currency0 = unspecified). Pulls fee from PM and forwards to
    ///         FeeCollector; returns int128 hookDelta on unspecified currency so
    ///         the user's ETH output is reduced by `fee`.
    function afterSwap(
        address sender,
        PoolKey calldata key,
        SwapParams calldata params,
        BalanceDelta delta,
        bytes calldata
    )
        external
        onlyPoolManager
        returns (bytes4, int128)
    {
        lastSwapBlock = uint64(block.number);

        // Hook-internal swaps (liquidation) bypass fee.
        if (sender == address(this))                return (IHooks.afterSwap.selector, 0);
        // Only handle SELL direction here. BUY handled in beforeSwap.
        if (params.zeroForOne)                      return (IHooks.afterSwap.selector, 0);
        if (params.amountSpecified >= 0)            return (IHooks.afterSwap.selector, 0);

        int128 ethOut = delta.amount0(); // currency0 = ETH = unspecified for sells
        if (ethOut <= 0) return (IHooks.afterSwap.selector, 0);

        uint256 fee = (uint256(uint128(ethOut)) * SWAP_FEE_BPS) / 10000;
        if (fee == 0) return (IHooks.afterSwap.selector, 0);

        poolManager.take(key.currency0, address(feeCollector), fee);

        return (IHooks.afterSwap.selector, int128(int256(fee)));
    }

    function afterAddLiquidity(
        address, PoolKey calldata, ModifyLiquidityParams calldata, BalanceDelta, BalanceDelta, bytes calldata
    ) external pure returns (bytes4, BalanceDelta) {
        revert InvalidAction();
    }
    function afterRemoveLiquidity(
        address, PoolKey calldata, ModifyLiquidityParams calldata, BalanceDelta, BalanceDelta, bytes calldata
    ) external pure returns (bytes4, BalanceDelta) {
        revert InvalidAction();
    }
    function beforeDonate(address, PoolKey calldata, uint256, uint256, bytes calldata) external pure returns (bytes4) {
        revert InvalidAction();
    }
    function afterDonate(address, PoolKey calldata, uint256, uint256, bytes calldata) external pure returns (bytes4) {
        revert InvalidAction();
    }

    // ─── Lending: borrow ────────────────────────────────────────────────────
    /// @notice Open or grow a position. Locks `collateralLOOP` and releases
    ///         `debtETH = collateralValue × 40 %` to the caller (minus 1% origination
    ///         fee routed to FeeCollector). The withdrawn ETH comes from a single
    ///         predicted "bound band" — the LDF band containing the position's
    ///         liquidation price (60 % of the current spot in ETH/LOOP).
    /// @param  collateralLOOP  amount of LOOP to lock as collateral.
    /// @return boundBand       LDF bandId the borrow drew from.
    /// @return debtETH         ETH debt (gross — net to user is `debtETH × 39 / 40`).
    function borrow(uint256 collateralLOOP)
        external
        nonReentrant
        returns (uint256 boundBand, uint256 debtETH)
    {
        if (!poolInitialized) revert PoolNotInitializedErr();
        if (block.number <= lastSwapBlock) revert SwapInSameBlock();
        if (collateralLOOP == 0) revert CollateralBelowMin();

        require(loop.transferFrom(msg.sender, address(this), collateralLOOP), "LoopPullFail");

        (uint160 sqrtP, int24 currentTick,,) = poolManager.getSlot0(_poolId());

        // Value collateral & size debt
        uint256 collateralValue = LDF.loopValueInEth(sqrtP, collateralLOOP);
        if (collateralValue < MIN_COLLATERAL_VALUE) revert CollateralBelowMin();

        // Liquidation price -> band
        uint256 spotEth = LDF.ethAtSqrtPrice(sqrtP);
        uint256 liqEth  = LDF.liquidationEthForBorrowEth(spotEth);
        boundBand = LDF.ethToBandId(liqEth);
        if (boundBand >= NUM_INITIAL_BANDS) revert InvalidBoundTick();

        // Resolve bound band: if the predicted band is FULLY BELOW currentTick
        // (cannot give us any ETH at all), step down to the next bandId. Bands
        // that STRADDLE currentTick are kept — _handleBorrow extracts ETH from
        // the upper sub-range and the LOOP returned by V4 stays in the hook
        // as protocol surplus.
        boundBand = _resolveBorrowBand(boundBand, currentTick);

        TickBand storage band = bands[boundBand];
        if (band.liquidity == 0) revert TickFull();
        // Reject only if band is FULLY below spot (no ETH side to draw)
        if (band.v4TickUpper <= currentTick) revert BoundAboveSpot();

        uint256 plannedDebt = collateralValue * LTV_BPS / 10_000;
        // Use straddle-aware L computation — handles both fully-above and
        // straddling positions correctly.
        uint128 lToRemove = LDF.liquidityForEthAtSpot(
            sqrtP, band.v4TickLower, band.v4TickUpper, plannedDebt
        );
        if (lToRemove == 0) revert TickFull();
        if (lToRemove > band.liquidity) revert TickFull();

        bytes memory ret = poolManager.unlock(abi.encode(
            Action.BORROW,
            abi.encode(boundBand, lToRemove, msg.sender)
        ));
        debtETH = abi.decode(ret, (uint256));

        band.liquidity   -= lToRemove;
        band.borrowedETH += debtETH;

        Position storage pos = positions[msg.sender][boundBand];
        pos.collateralLOOP += collateralLOOP;
        pos.debtETH        += debtETH;
        pos.openedAtBlock   = uint64(block.number);

        totalOutstandingDebt  += debtETH;
        totalCollateralLocked += collateralLOOP;

        uint256 origFee   = debtETH * ORIG_FEE_BPS / LTV_BPS;
        uint256 netToUser = debtETH - origFee;
        emit Borrowed(msg.sender, boundBand, collateralLOOP, debtETH, netToUser, origFee);
    }

    // ─── Lending: repay ─────────────────────────────────────────────────────
    /// @notice Repay (partial or full) a position. Releases collateral pro-rata
    ///         to the fraction of debt repaid. ETH refills the band currently
    ///         closest above spot — preserves protocol depth even if spot
    ///         drifted between borrow and repay.
    function repay(uint256 boundBand) external payable nonReentrant {
        Position storage pos = positions[msg.sender][boundBand];
        if (pos.debtETH == 0) revert NoOpenPosition();
        if (block.number < pos.openedAtBlock + REPAY_COOLDOWN_BLOCKS) revert CooldownActive();
        uint256 amount = msg.value;
        if (amount == 0 || amount > pos.debtETH) revert RepayAmountMismatch();

        bool full = (amount == pos.debtETH);
        uint256 collateralReturn = full
            ? pos.collateralLOOP
            : pos.collateralLOOP * amount / pos.debtETH;

        // Refill into the BOUND band (sub-range fallback if it now straddles spot).
        // The unlock callback wraps the modifyLiquidity + settle.
        bytes memory ret = poolManager.unlock(abi.encode(
            Action.REPAY,
            abi.encode(boundBand, amount)
        ));
        uint256 refilled = abi.decode(ret, (uint256));

        TickBand storage bband = bands[boundBand];
        if (bband.borrowedETH >= amount) bband.borrowedETH -= amount;
        else bband.borrowedETH = 0;

        pos.debtETH        -= amount;
        pos.collateralLOOP -= collateralReturn;
        if (full) delete positions[msg.sender][boundBand];

        totalOutstandingDebt  -= amount;
        totalCollateralLocked -= collateralReturn;

        require(loop.transfer(msg.sender, collateralReturn), "ReturnFailed");

        // Anything not absorbed by the LP refill (rounding leftover OR no valid
        // sub-range above spot) is forwarded to FeeCollector. The user has
        // already extinguished their debt; surplus accrues to the protocol.
        if (refilled < amount) {
            uint256 toFc = amount - refilled;
            (bool fcSent,) = address(feeCollector).call{value: toFc}("");
            if (!fcSent) revert EthTransferFailed();
        }

        emit Repaid(msg.sender, boundBand, amount, collateralReturn, full);
    }

    // ─── Lending: liquidate ─────────────────────────────────────────────────
    /// @notice Permissionlessly liquidate an underwater (collateral < debt × 1.5)
    ///         position. Sells the entire collateral via V4 swap, pays a 1%-of-debt
    ///         bounty to the caller, and refills the surplus ETH back into a band
    ///         above the post-swap spot. No LOOP burn — the protocol heals itself.
    function liquidate(address user, uint256 boundBand) external nonReentrant {
        // Hard cap: at most one liquidation per block. Combined with the
        // SwapBlockedByLiquidation rule (beforeSwap), this neutralises both
        // legs of the atomic-bundle MEV attack:
        //   1. atomic 24-liq batching — impossible (1/block ceiling)
        //   2. cross-pool buyback after lo0p crash — impossible (swap blocked)
        if (block.number <= lastLiquidationBlock) revert OneLiquidationPerBlock();

        Position storage pos = positions[user][boundBand];
        if (pos.debtETH == 0) revert NoOpenPosition();

        (uint160 sqrtP,,,) = poolManager.getSlot0(_poolId());
        uint256 collValue = LDF.loopValueInEth(sqrtP, pos.collateralLOOP);
        if (collValue * 10_000 >= pos.debtETH * LIQUIDATION_THRESHOLD_BPS) revert NotUnderwater();

        uint256 collateral = pos.collateralLOOP;
        uint256 debt       = pos.debtETH;
        // 1% of debt for incentive, capped at MAX_LIQUIDATION_BOUNTY so big positions
        // don't drain a disproportionate ETH amount to the bot. Surplus stays with
        // the protocol (refilled to the bound band or routed to FeeCollector).
        uint256 bounty     = debt * LIQUIDATION_BOUNTY_BPS / 10_000;
        if (bounty > MAX_LIQUIDATION_BOUNTY) bounty = MAX_LIQUIDATION_BOUNTY;

        // Clear position before external interaction
        delete positions[user][boundBand];
        totalOutstandingDebt  -= debt;
        totalCollateralLocked -= collateral;

        // Mark this block as a liquidation block; external swaps in this block
        // will be rejected by beforeSwap. Hook's own internal swap inside
        // _handleLiquidate is identified via sender == address(this) and
        // bypasses the check naturally.
        lastLiquidationBlock = uint64(block.number);
        bytes memory ret = poolManager.unlock(abi.encode(
            Action.LIQUIDATE,
            abi.encode(collateral, bounty, msg.sender, boundBand)
        ));
        (uint256 ethProceeds, uint256 refillETH, uint256 actualBounty) =
            abi.decode(ret, (uint256, uint256, uint256));

        TickBand storage bband = bands[boundBand];
        if (bband.borrowedETH >= debt) bband.borrowedETH -= debt;
        else bband.borrowedETH = 0;

        emit Liquidated(user, msg.sender, boundBand, collateral, ethProceeds, actualBounty, refillETH);
    }

    // ─── Unlock callback ────────────────────────────────────────────────────
    enum Action { SEED_BANDS, BORROW, REPAY, LIQUIDATE, OWNER_BUY }

    function unlockCallback(bytes calldata data) external onlyPoolManager returns (bytes memory) {
        (Action action, bytes memory payload) = abi.decode(data, (Action, bytes));

        if (action == Action.SEED_BANDS) {
            (uint256 fromBand, uint256 toBand) = abi.decode(payload, (uint256, uint256));
            for (uint256 i = fromBand; i < toBand; i++) {
                _seedSingleBand(i);
            }
            return "";
        } else if (action == Action.BORROW) {
            return _handleBorrow(payload);
        } else if (action == Action.REPAY) {
            return _handleRepay(payload);
        } else if (action == Action.LIQUIDATE) {
            return _handleLiquidate(payload);
        } else if (action == Action.OWNER_BUY) {
            return _handleOwnerBuy(payload);
        }
        revert InvalidAction();
    }

    function _handleBorrow(bytes memory payload) internal returns (bytes memory) {
        (uint256 boundBand, uint128 lToRemove, address recipient) =
            abi.decode(payload, (uint256, uint128, address));
        TickBand storage band = bands[boundBand];

        (BalanceDelta delta,) = poolManager.modifyLiquidity(
            poolKey,
            ModifyLiquidityParams({
                tickLower: band.v4TickLower,
                tickUpper: band.v4TickUpper,
                liquidityDelta: -int256(uint256(lToRemove)),
                salt: bytes32(0)
            }),
            ""
        );
        int128 a0 = delta.amount0();
        int128 a1 = delta.amount1();
        require(a0 > 0, "ZeroEth");
        uint256 actualETH = uint256(uint128(a0));

        poolManager.take(CurrencyLibrary.ADDRESS_ZERO, address(this), actualETH);

        // If the bound band straddled currentTick, V4 also returned LOOP from
        // the lower sub-range (a1 > 0). We MUST take it to settle the delta;
        // it stays in the hook as protocol surplus.
        if (a1 > 0) {
            uint256 loopBack = uint256(uint128(a1));
            poolManager.take(poolKey.currency1, address(this), loopBack);
        }

        uint256 origFee   = actualETH * ORIG_FEE_BPS / LTV_BPS;
        uint256 netToUser = actualETH - origFee;

        (bool s1,) = address(feeCollector).call{value: origFee}("");
        if (!s1) revert EthTransferFailed();
        (bool s2,) = recipient.call{value: netToUser}("");
        if (!s2) revert EthTransferFailed();

        return abi.encode(actualETH);
    }

    function _handleRepay(bytes memory payload) internal returns (bytes memory) {
        (uint256 boundBand, uint256 ethProvided) = abi.decode(payload, (uint256, uint256));
        uint256 spent = _refillBoundBand(boundBand, ethProvided);
        return abi.encode(spent);
    }

    function _handleLiquidate(bytes memory payload) internal returns (bytes memory) {
        (uint256 collateral, uint256 bounty, address liquidator, uint256 boundBand) =
            abi.decode(payload, (uint256, uint256, address, uint256));

        // Sell collateral LOOP for ETH (V4 native swap math through our LP)
        BalanceDelta swapDelta = poolManager.swap(
            poolKey,
            SwapParams({
                zeroForOne: false,
                amountSpecified: -int256(collateral),
                sqrtPriceLimitX96: TickMath.MAX_SQRT_PRICE - 1
            }),
            ""
        );
        int128 a0 = swapDelta.amount0();
        int128 a1 = swapDelta.amount1();
        require(a0 > 0, "NoEthOut");
        require(a1 < 0, "NoLoopIn");
        uint256 ethOut   = uint256(uint128(a0));
        uint256 loopOwed = uint256(uint128(-a1));

        // Settle the LOOP we owe
        poolManager.sync(poolKey.currency1);
        require(loop.transfer(address(poolManager), loopOwed), "LoopXfer");
        poolManager.settle();

        // Take all the ETH out
        poolManager.take(CurrencyLibrary.ADDRESS_ZERO, address(this), ethOut);

        // Pay bounty
        uint256 actualBounty = bounty > ethOut ? ethOut : bounty;
        if (actualBounty > 0) {
            (bool sb,) = liquidator.call{value: actualBounty}("");
            if (!sb) revert EthTransferFailed();
        }

        // Refill the BOUND band (the one this position originally borrowed from)
        // — self-healing in the strict sense. If the post-swap currentTick has
        // moved up enough that the bound band now straddles spot, we refill a
        // sub-range [alignedUp(currentTick), tickUpper] which is still ETH-only
        // valid. If currentTick has moved past tickUpper entirely, the bound band
        // is below spot and can't be refilled with ETH alone — surplus → FC.
        uint256 refillETH = ethOut - actualBounty;
        if (refillETH > 0) {
            uint256 spentOnRefill = _refillBoundBand(boundBand, refillETH);
            if (spentOnRefill < refillETH) {
                uint256 toFc = refillETH - spentOnRefill;
                (bool fcSent,) = address(feeCollector).call{value: toFc}("");
                if (!fcSent) revert EthTransferFailed();
            }
        }

        return abi.encode(ethOut, refillETH, actualBounty);
    }

    /// @dev Pre-launch ETH→LOOP swap executed during ownerBootstrapBuy.
    ///      Hook is `sender` of the swap so beforeSwap bypasses the !started
    ///      and lastLiquidationBlock gates. The 1% swap fee was already taken
    ///      from msg.value in ownerBootstrapBuy and forwarded to FeeCollector,
    ///      so `ethIn` here is post-fee. LOOP is taken directly to the owner's
    ///      wallet via PoolManager.take — hook never holds it.
    function _handleOwnerBuy(bytes memory payload) internal returns (bytes memory) {
        (uint256 ethIn, address recipient) = abi.decode(payload, (uint256, address));

        // Settle ETH (hook owes ETH to PM for the swap input)
        poolManager.sync(CurrencyLibrary.ADDRESS_ZERO);
        poolManager.settle{value: ethIn}();

        // Exact-input ETH→LOOP swap through the lo0p curve
        BalanceDelta delta = poolManager.swap(
            poolKey,
            SwapParams({
                zeroForOne: true,
                amountSpecified: -int256(ethIn),
                sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
            }),
            ""
        );

        int128 a1 = delta.amount1();
        require(a1 > 0, "NoLoopOut");
        uint256 loopOut = uint256(uint128(a1));

        // Send LOOP directly to the owner's wallet
        poolManager.take(poolKey.currency1, recipient, loopOut);

        return abi.encode(loopOut);
    }

    function _seedSingleBand(uint256 bandId) internal {
        (int24 tickLower, int24 tickUpper) = LDF.bandToV4Ticks(bandId);
        uint256 loopAlloc = LDF.loopAllocForBand(bandId);
        uint128 liquidity = LDF.liquidityForLoopOnly(tickLower, tickUpper, loopAlloc);

        // modifyLiquidity with positive delta → hook owes LOOP (currency1)
        (BalanceDelta delta, ) = poolManager.modifyLiquidity(
            poolKey,
            ModifyLiquidityParams({
                tickLower: tickLower,
                tickUpper: tickUpper,
                liquidityDelta: int128(liquidity),
                salt: bytes32(0)
            }),
            ""
        );

        // Settle the LOOP (currency1) we owe to PM. amount1 will be negative
        // (we owe), absolute value is what to settle.
        int128 a1 = delta.amount1();
        if (a1 < 0) {
            uint256 owed = uint256(uint128(-a1));
            poolManager.sync(poolKey.currency1);
            // Use forceTransfer-style: hook holds LOOP, transfers to PM
            // (loop.transfer is regular ERC20 transfer)
            require(loop.transfer(address(poolManager), owed), "TransferFailed");
            poolManager.settle();
        }

        bands[bandId] = TickBand({
            v4TickLower: tickLower,
            v4TickUpper: tickUpper,
            liquidity:   liquidity,
            borrowedETH: 0
        });
        emit BandSeeded(bandId, tickLower, tickUpper, loopAlloc, liquidity);
    }

    // ─── Views ──────────────────────────────────────────────────────────────

    /// @notice Current spot V4 price.
    function currentSqrtPriceX96() public view returns (uint160 sqrtPriceX96) {
        (sqrtPriceX96, , , ) = poolManager.getSlot0(_poolId());
    }

    function _poolId() internal view returns (PoolId) {
        return PoolIdLibrary.toId(poolKey);
    }

    function getBand(uint256 bandId) external view returns (TickBand memory) {
        return bands[bandId];
    }

    function getPosition(address user, uint256 boundBand) external view returns (Position memory) {
        return positions[user][boundBand];
    }

    /// @notice Quote how much ETH a fresh borrow against `collateralLOOP` would
    ///         release at the current spot, plus the predicted bound band and
    ///         whether enough liquidity is available there.
    function quoteBorrow(uint256 collateralLOOP)
        external
        view
        returns (uint256 boundBand, uint256 debtETH, uint256 netToUser, bool feasible)
    {
        if (collateralLOOP == 0) return (0, 0, 0, false);
        (uint160 sqrtP, int24 currentTick,,) = poolManager.getSlot0(_poolId());
        uint256 collateralValue = LDF.loopValueInEth(sqrtP, collateralLOOP);
        if (collateralValue < MIN_COLLATERAL_VALUE) return (0, 0, 0, false);

        uint256 spotEth = LDF.ethAtSqrtPrice(sqrtP);
        uint256 liqEth  = LDF.liquidationEthForBorrowEth(spotEth);
        boundBand = LDF.ethToBandId(liqEth);
        if (boundBand >= NUM_INITIAL_BANDS) return (boundBand, 0, 0, false);

        // Resolve bound band — keep straddling bands valid (they yield ETH +
        // residual LOOP via dual-token extraction).
        boundBand = _resolveBorrowBand(boundBand, currentTick);

        debtETH   = collateralValue * LTV_BPS / 10_000;
        uint256 origFee = collateralValue * ORIG_FEE_BPS / 10_000;
        netToUser = debtETH > origFee ? debtETH - origFee : 0;

        TickBand storage band = bands[boundBand];
        if (band.liquidity == 0 || band.v4TickUpper <= currentTick) return (boundBand, debtETH, netToUser, false);
        uint128 lNeeded = LDF.liquidityForEthAtSpot(
            sqrtP, band.v4TickLower, band.v4TickUpper, debtETH
        );
        feasible = (lNeeded > 0 && lNeeded <= band.liquidity);
    }

    /// @notice True iff a (user, boundBand) position is currently underwater
    ///         (collateral value < debt × 150 %).
    function isUnderwater(address user, uint256 boundBand) external view returns (bool) {
        Position storage pos = positions[user][boundBand];
        if (pos.debtETH == 0) return false;
        (uint160 sqrtP,,,) = poolManager.getSlot0(_poolId());
        uint256 collValue = LDF.loopValueInEth(sqrtP, pos.collateralLOOP);
        return collValue * 10_000 < pos.debtETH * LIQUIDATION_THRESHOLD_BPS;
    }

    /// @dev Closest band still STRICTLY ABOVE `currentTick` (i.e. ETH-only single-
    ///      sided). Bands are stored in monotone order: band 0 = highest tickLower,
    ///      band N = lowest. Returns the LAST band that still satisfies `tickLower >
    ///      currentTick`, or `(0, false)` if every band is at/below currentTick.
    function _findRefillBand(int24 currentTick) internal view returns (uint256 bandId, bool found) {
        for (uint256 i = 0; i < NUM_INITIAL_BANDS; i++) {
            if (bands[i].v4TickLower > currentTick) {
                bandId = i;
                found = true;
            } else {
                break;
            }
        }
    }

    /// @dev Resolve a candidate borrow band so that it is STRICTLY above
    ///      currentTick. If the candidate straddles or is below currentTick
    ///      (the "dead zone"), step DOWN through bandIds (= step toward higher
    ///      V4 ticks) until we land on a band that is fully above currentTick.
    ///      Returns 0 unchanged if no shift is needed; caller will fail with
    ///      BoundAboveSpot only if even bandId 0 cannot satisfy.
    function _resolveBorrowBand(uint256 candidate, int24 currentTick) internal view returns (uint256) {
        // bands[i].v4TickLower is monotone DECREASING with i
        // (band 0 = highest tickLower, band 29 = lowest)
        // To find a band with tickLower > currentTick, we step toward LOWER bandId.
        while (candidate > 0 && bands[candidate].v4TickLower <= currentTick) {
            candidate--;
        }
        return candidate;
    }

    /// @dev Inject `ethAmount` back into `boundBand` as ETH-only single-sided LP.
    ///      If currentTick straddles the bound band, uses the sub-range
    ///      [alignedUp(currentTick), boundBand.tickUpper] which is still strictly
    ///      above spot. If currentTick has passed boundBand.tickUpper entirely,
    ///      no refill is possible (returns 0).
    /// @return spent  ETH wei actually consumed by the modifyLiquidity call.
    function _refillBoundBand(uint256 boundBand, uint256 ethAmount) internal returns (uint256 spent) {
        TickBand storage bb = bands[boundBand];
        (, int24 currentTick,,) = poolManager.getSlot0(_poolId());

        int24 refillLower;
        int24 refillUpper = bb.v4TickUpper;
        bool fullRange;

        uint256 targetBandId = boundBand; // tracks the band whose L counter we should bump

        if (currentTick < bb.v4TickLower) {
            // CASE 1: Bound band fully above spot — refill its full range
            refillLower = bb.v4TickLower;
            fullRange = true;
        } else if (currentTick < bb.v4TickUpper) {
            // CASE 2: Bound band straddles spot — use upper sub-range only
            refillLower = LDF.alignUpToSpacing(currentTick);
            if (refillLower <= currentTick) refillLower += LDF.TICK_SPACING;
            if (refillLower >= refillUpper) return 0;
        } else {
            // CASE 3: Bound band fully BELOW spot — try the closest OTHER band
            // still strictly above currentTick. Preserves "self-healing" (LP
            // gets refreshed) at the cost of attributing refill to a different
            // band than where the borrow originated.
            (uint256 altBand, bool found) = _findRefillBand(currentTick);
            if (!found) return 0;                // no band above — caller → FC
            TickBand storage ab = bands[altBand];
            refillLower = ab.v4TickLower;
            refillUpper = ab.v4TickUpper;
            fullRange = true;
            targetBandId = altBand;
        }

        uint128 lToAdd = LDF.liquidityForEthOnly(refillLower, refillUpper, ethAmount);
        if (lToAdd == 0) return 0;

        (BalanceDelta lpDelta,) = poolManager.modifyLiquidity(
            poolKey,
            ModifyLiquidityParams({
                tickLower: refillLower,
                tickUpper: refillUpper,
                liquidityDelta: int256(uint256(lToAdd)),
                salt: bytes32(0)
            }),
            ""
        );
        int128 owed0 = lpDelta.amount0();
        if (owed0 < 0) {
            spent = uint256(uint128(-owed0));
            poolManager.settle{value: spent}();
        }

        // Update the L counter of whichever band actually received the refill.
        // For straddle (sub-range) refills we don't update the counter — that
        // V4 LP exists as a separate position not tracked in our bands map.
        if (fullRange) bands[targetBandId].liquidity += lToAdd;
    }

    receive() external payable {}
}

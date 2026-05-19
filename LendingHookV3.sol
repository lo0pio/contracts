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
import {LiquidityAmounts} from "@uniswap/v4-core/test/utils/LiquidityAmounts.sol";
import {StateLibrary} from "@uniswap/v4-core/src/libraries/StateLibrary.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title  LendingHookV3 — community-LP lending AMM for existing tokens
/// @notice Generalizes the lo0p model so anyone can spin up a borrowable market
///         for an already-deployed ERC20. Unlike V2 (which mints its own token
///         supply and seeds 100 LDF bands the hook owns), V3 holds a single
///         full-range V4 LP position that LPs deposit into via this hook (it
///         behaves like an ERC4626-style vault for an ETH/TOKEN pair).
///
///         Roles:
///           · LP        — calls deposit() with ETH + TOKEN, earns swap fees
///                         (auto-compounded into the position) plus a share of
///                         every borrow's origination fee.
///           · Borrower  — calls borrow(collateralTOKEN), receives ETH against
///                         TOKEN collateral at 40 % LTV. Repays via repay().
///           · Liquidator— calls liquidate(user) when collateral × spot <
///                         1.5 × debt. Earns up to 0.01 ETH bounty. The locked
///                         collateral + bot's debt payment refill the LP,
///                         growing the position for remaining LPs.
///
///         Spot is held constant on borrow via proportional withdraw (the V2
///         insight): when ETH is pulled out of the LP, a matching amount of
///         TOKEN is also pulled and held as `loanReserveToken` for that user.
///         On repay, both flow back together — the LP is restored to its
///         pre-borrow state.
contract LendingHookV3 is IHooks, IUnlockCallback, ERC20 {
    using StateLibrary for IPoolManager;

    // ─── Constants ──────────────────────────────────────────────────────────
    uint256 public constant LTV_BPS                   = 4000;       // 40 %
    uint256 public constant ORIG_FEE_BPS              = 100;        // 1 % of debt

    /// @notice Swap fee is split 50/50 between LPs and protocol. V4's native
    ///         `fee` field handles the LP half automatically — the PoolManager
    ///         accrues it into LP positions, harvested on modifyLiquidity. The
    ///         protocol half is skimmed in beforeSwap and routed to FeeCollector.
    ///         Total user-paid fee = 1 % (0.5 % LP + 0.5 % protocol).
    uint24  public constant LP_SWAP_FEE_PIPS          = 5_000;      // 0.5 %  (V4 fee field is in pips: 1e6 = 100 %)
    uint256 public constant PROTOCOL_SWAP_FEE_BPS     = 50;         // 0.5 %  (hook skim → FeeCollector)

    uint256 public constant LIQUIDATION_THRESHOLD_BPS = 15_000;     // 150 %
    /// @notice Liquidator pays full debt in ETH and receives collateral TOKEN
    ///         priced at spot × (1 - 2.5 %), i.e. 2.5 % more TOKEN than
    ///         a spot-equivalent purchase. This is the bot's profit per liq.
    ///         Replaces V2's fixed-cap bounty — now scales with position size.
    uint256 public constant LIQUIDATION_DISCOUNT_BPS  = 250;        // 2.5 %
    uint256 public constant REPAY_COOLDOWN_BLOCKS     = 2;

    /// @notice Each borrow call must produce at least MIN_DEBT new debt. Plus
    ///         every partial repay must leave at least MIN_DEBT remaining (or
    ///         go to zero). Keeps dust positions out of state.
    uint256 public constant MIN_DEBT                  = 0.1 ether;

    /// @notice Flat fee charged on position close (full repay only). Goes to
    ///         FeeCollector. Skipped on partial repay so users aren't penalized
    ///         for paying down early.
    uint256 public constant POSITION_CLOSE_FEE        = 0.01 ether;

    /// @notice Split of origination fee. PROTOCOL_FEE_BPS goes to FeeCollector
    ///         (revenue → LOOP holders); the rest is added back to the pool's
    ///         ETH side, growing every LP's share value.
    uint256 public constant PROTOCOL_FEE_BPS = 5_000;  // 50 %

    /// @notice Minimum shares minted to dead address on first deposit, to
    ///         prevent inflation attack (ERC4626 pattern).
    uint256 public constant MINIMUM_SHARES = 1_000;

    /// @notice Tick spacing for the V4 pool. 60 is a Uniswap-V3 standard for
    ///         1 % fee tier; gives wide enough range for full-range LP.
    int24 public constant TICK_SPACING = 60;

    // ─── Errors ─────────────────────────────────────────────────────────────
    error NotOwner();
    error NotPoolManager();
    error PoolAlreadyInitialized();
    error PoolNotInitializedErr();
    error UnauthorizedLP();
    error ZeroAddress();
    error ZeroAmount();
    error Reentrancy();
    error InvalidAction();
    error EthTransferFailed();
    error InvalidPoolKey();
    error SwapInSameBlock();
    error CollateralBelowMin();
    error DebtBelowMin();
    error InvalidRepayAmount();
    error NoOpenPosition();
    error CooldownActive();
    error RepayAmountMismatch();
    error NotUnderwater();
    error InsufficientLiquidity();
    error RatioMismatch();
    error MinSharesNotMet();
    error SlippageExceeded();
    error OneLiquidationPerBlock();
    error BlockedByLiquidation();

    // ─── Immutables ─────────────────────────────────────────────────────────
    IPoolManager   public immutable poolManager;
    IERC20         public immutable token;          // e.g. SATO
    address        public immutable feeCollector;   // ours → LOOP holders
    int24          public immutable tickLower;      // full-range, spacing-aligned
    int24          public immutable tickUpper;

    /// @notice Hook owner. Sets initial sqrtPrice on initializePool, can
    ///         renounce afterwards. No emergency lever beyond that.
    address public owner;

    // ─── State ──────────────────────────────────────────────────────────────
    PoolKey public poolKey;
    bool    public poolInitialized;

    /// @notice LP-side state. `realETH` and `realToken` mirror the V4 position
    ///         the hook holds, MINUS amounts currently lent out to borrowers
    ///         (those live in per-position loanReserveToken). The invariant is:
    ///             v4PositionETH   = realETH + totalDebt
    ///             v4PositionToken = realToken + totalLoanReserveToken
    ///         But realETH/realToken are what's actually in the V4 position
    ///         RIGHT NOW; the rest has been pulled out via proportional withdraw.
    uint256 public realETH;
    uint256 public realToken;
    uint128 public liquidity;          // current V4 position liquidity
    // Share token state lives on the inherited ERC20 (balanceOf / totalSupply).
    // The hook itself IS the LP share token — e.g. "lo0pED SATO/ETH".
    // Transferable, composable with the rest of DeFi.

    /// @notice Per-user lending position. One position per user (additive
    ///         borrows extend it; partial repay shrinks it pro-rata).
    struct Position {
        uint256 collateral;        // locked TOKEN
        uint256 debt;              // outstanding ETH owed
        uint256 loanReserveToken;  // TOKEN proportionally pulled from LP at borrow time
        uint64  openedAtBlock;
    }
    mapping(address => Position) public positions;

    uint256 public totalDebt;
    uint256 public totalCollateralLocked;
    uint256 public totalLoanReserveToken;

    /// @notice Block of the most recent swap. Borrow is locked out in the
    ///         same block to prevent pump-then-borrow oracle manipulation.
    ///         Liquidate is NOT locked out by this — bots must be able to
    ///         react to the swap that just made a position underwater.
    uint64 public lastSwapBlock;

    /// @notice Block of the most recent liquidation. External swaps in the
    ///         same block revert (`BlockedByLiquidation`), neutralising
    ///         the cross-pool buyback leg of the atomic-bundle MEV attack.
    ///         Hard cap of one liquidation per block prevents atomic batch
    ///         liquidations from being chained.
    uint64 public lastLiquidationBlock;

    // ─── Events ─────────────────────────────────────────────────────────────
    event PoolReady(PoolId indexed id, uint160 sqrtPriceX96, int24 currentTick);
    event Deposit(address indexed lp, uint256 ethIn, uint256 tokenIn, uint256 sharesOut);
    event Withdraw(address indexed lp, uint256 sharesIn, uint256 ethOut, uint256 tokenOut);
    event Borrowed(address indexed user, uint256 collateralIn, uint256 debtETH, uint256 netToUser, uint256 originationFee);
    event Repaid(address indexed user, uint256 ethIn, uint256 collateralReturned, bool full);
    event Liquidated(
        address indexed victim,
        address indexed liquidator,
        uint256 collateral,
        uint256 debtETH,
        uint256 tokenToBot,
        uint256 residualToken
    );
    event Swapped(address indexed origin, bool zeroForOne, uint256 amountIn, uint256 feeETH);
    event OwnerTransferred(address indexed previous, address indexed next);

    // ─── Modifiers ──────────────────────────────────────────────────────────
    uint256 private _locked = 1;
    modifier nonReentrant() {
        if (_locked != 1) revert Reentrancy();
        _locked = 2;
        _;
        _locked = 1;
    }
    modifier onlyOwner()       { if (msg.sender != owner) revert NotOwner(); _; }
    modifier onlyPoolManager() { if (msg.sender != address(poolManager)) revert NotPoolManager(); _; }

    // ─── Constructor ────────────────────────────────────────────────────────
    /// @param  poolManager_  V4 PoolManager.
    /// @param  token_        Underlying ERC20 that pairs against ETH.
    /// @param  feeCollector_ Where origination fees route (LOOP holder revenue).
    /// @param  owner_        Hook owner (sets initial sqrtPrice, can renounce).
    /// @param  shareName_    Display name of the LP share token, e.g.
    ///                       "lo0pED SATO/ETH LP".
    /// @param  shareSymbol_  Display symbol, e.g. "loSATO-ETH".
    constructor(
        IPoolManager poolManager_,
        IERC20 token_,
        address feeCollector_,
        address owner_,
        string memory shareName_,
        string memory shareSymbol_
    ) ERC20(shareName_, shareSymbol_) {
        if (
            address(poolManager_) == address(0) || address(token_) == address(0)
                || feeCollector_ == address(0) || owner_ == address(0)
        ) revert ZeroAddress();

        poolManager  = poolManager_;
        token        = token_;
        feeCollector = feeCollector_;
        owner        = owner_;

        // Full-range, spacing-aligned. MIN/MAX_TICK are usable bounds.
        int24 minUsable = (TickMath.MIN_TICK / TICK_SPACING) * TICK_SPACING;
        int24 maxUsable = (TickMath.MAX_TICK / TICK_SPACING) * TICK_SPACING;
        tickLower = minUsable;
        tickUpper = maxUsable;

        Hooks.validateHookPermissions(IHooks(address(this)), getHookPermissions());
        emit OwnerTransferred(address(0), owner_);
    }

    // ─── Hook permissions ───────────────────────────────────────────────────
    function getHookPermissions() public pure returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize:           true,
            afterInitialize:            true,
            beforeAddLiquidity:         true,
            afterAddLiquidity:          false,
            beforeRemoveLiquidity:      true,
            afterRemoveLiquidity:       false,
            beforeSwap:                 true,
            afterSwap:                  true,
            beforeDonate:               false,
            afterDonate:                false,
            beforeSwapReturnDelta:      true,
            afterSwapReturnDelta:       true,
            afterAddLiquidityReturnDelta:    false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    // ─── Ownership ──────────────────────────────────────────────────────────
    function renounceOwnership() external onlyOwner {
        emit OwnerTransferred(owner, address(0));
        owner = address(0);
    }

    // ─── Pool setup ─────────────────────────────────────────────────────────

    /// @notice Owner-only. Initialize the V4 pool at a chosen sqrtPriceX96.
    ///         Should be calibrated to current market spot of the token to
    ///         avoid immediate arbitrage drain on the first deposit.
    function initializePool(uint160 sqrtPriceX96) external onlyOwner {
        if (poolInitialized) revert PoolAlreadyInitialized();

        PoolKey memory key = PoolKey({
            currency0:   CurrencyLibrary.ADDRESS_ZERO,           // native ETH
            currency1:   Currency.wrap(address(token)),
            fee:         LP_SWAP_FEE_PIPS,                       // 0.5 % auto-distributed to LPs by V4
            tickSpacing: TICK_SPACING,
            hooks:       IHooks(address(this))
        });
        poolKey = key;
        poolManager.initialize(key, sqrtPriceX96);
        poolInitialized = true;

        (, int24 currentTick,,) = poolManager.getSlot0(_poolId());
        emit PoolReady(_poolId(), sqrtPriceX96, currentTick);
    }

    // ─── LP: deposit / withdraw ─────────────────────────────────────────────

    /// @notice Deposit ETH + TOKEN at the current pool ratio. First depositor
    ///         can deposit at any ratio (effectively setting the initial LP
    ///         price; should match market or get arbed). Subsequent deposits
    ///         must match `realETH / realToken` within 0.1 % tolerance.
    /// @param  tokenIn      TOKEN amount the LP is contributing.
    /// @param  minSharesOut Slippage floor on minted shares.
    /// @return sharesOut    Number of shares credited to msg.sender.
    function deposit(uint256 tokenIn, uint256 minSharesOut)
        external
        payable
        nonReentrant
        returns (uint256 sharesOut)
    {
        if (!poolInitialized) revert PoolNotInitializedErr();
        // Same-block liquidation lockout: closes the sandwich vector where a
        // bot deposits → triggers liq (collateral residual boosts LP) →
        // withdraws to capture the bonus in one tx. Long-term LPs only.
        if (block.number == lastLiquidationBlock) revert BlockedByLiquidation();
        uint256 ethIn = msg.value;
        if (ethIn == 0 || tokenIn == 0) revert ZeroAmount();

        require(token.transferFrom(msg.sender, address(this), tokenIn), "PullFail");

        if (totalSupply() == 0) {
            // Bootstrap: first depositor sets the ratio. Mint sqrt(eth*token)
            // minus MINIMUM_SHARES (burned to address(0) forever) to defuse
            // the share-inflation attack.
            uint256 totalMint = _sqrt(ethIn * tokenIn);
            if (totalMint <= MINIMUM_SHARES) revert MinSharesNotMet();
            sharesOut = totalMint - MINIMUM_SHARES;
            _mint(address(0xdead), MINIMUM_SHARES);
        } else {
            // Ratio enforcement: ethIn / tokenIn must match realETH / realToken
            // within tolerance. Cross-multiply to avoid div.
            // Acceptable if |ethIn × realToken - tokenIn × realETH| < 1‰ of the larger product.
            uint256 lhs = ethIn * realToken;
            uint256 rhs = tokenIn * realETH;
            uint256 maxSide = lhs > rhs ? lhs : rhs;
            uint256 diff = lhs > rhs ? lhs - rhs : rhs - lhs;
            if (diff * 1_000 > maxSide) revert RatioMismatch();

            // Pro-rata share mint. Use ETH side as the basis.
            sharesOut = ethIn * totalSupply() / realETH;
        }
        if (sharesOut < minSharesOut) revert SlippageExceeded();
        _mint(msg.sender, sharesOut);

        // Mint into the V4 full-range position.
        bytes memory ret = poolManager.unlock(abi.encode(
            Action.LP_ADD, abi.encode(ethIn, tokenIn)
        ));
        (uint128 lqAdded) = abi.decode(ret, (uint128));
        liquidity += lqAdded;
        realETH   += ethIn;
        realToken += tokenIn;

        emit Deposit(msg.sender, ethIn, tokenIn, sharesOut);
    }

    /// @notice Burn shares, withdraw proportional ETH + TOKEN. Subject to
    ///         current pool composition: if borrowers have pulled ETH out, the
    ///         LP gets back less ETH and more TOKEN than they deposited.
    function withdraw(uint256 sharesIn, uint256 minEthOut, uint256 minTokenOut)
        external
        nonReentrant
        returns (uint256 ethOut, uint256 tokenOut)
    {
        if (sharesIn == 0) revert ZeroAmount();
        if (balanceOf(msg.sender) < sharesIn) revert NoOpenPosition();
        // Symmetric lockout to deposit: prevents the same-tx
        // deposit→liquidate→withdraw sandwich.
        if (block.number == lastLiquidationBlock) revert BlockedByLiquidation();

        uint256 supplyBefore = totalSupply();
        // Pre-compute the target amounts for the slippage check + accounting.
        uint256 ethTarget = realETH   * sharesIn / supplyBefore;
        uint256 tokTarget = realToken * sharesIn / supplyBefore;
        if (ethTarget < minEthOut || tokTarget < minTokenOut) revert SlippageExceeded();

        _burn(msg.sender, sharesIn);

        uint128 lqToBurn = uint128(uint256(liquidity) * sharesIn / supplyBefore);
        if (lqToBurn > liquidity) lqToBurn = liquidity;
        liquidity -= lqToBurn;

        bytes memory ret = poolManager.unlock(abi.encode(
            Action.LP_REMOVE,
            abi.encode(lqToBurn, ethTarget, tokTarget, msg.sender)
        ));
        // _handleLpRemove returns the ACTUAL amounts V4 paid out, which may
        // differ from `ethTarget`/`tokTarget` by V4 rounding AND fee accrual.
        // V4's auto-compounded swap fees on the LP position can make the
        // actual exceed the target. Use actuals for caller-facing return,
        // but cap the state-mirror decrement to what we tracked (the surplus
        // — i.e. accumulated fees — silently exits the mirror).
        (ethOut, tokenOut) = abi.decode(ret, (uint256, uint256));
        uint256 ethDec = ethOut > realETH   ? realETH   : ethOut;
        uint256 tokDec = tokenOut > realToken ? realToken : tokenOut;
        realETH   -= ethDec;
        realToken -= tokDec;

        emit Withdraw(msg.sender, sharesIn, ethOut, tokenOut);
    }

    // ─── Borrow ─────────────────────────────────────────────────────────────

    /// @notice Lock TOKEN, borrow ETH at 40 % LTV. The pool's ETH side shrinks
    ///         by `grossDebt` and the TOKEN side shrinks by the proportional
    ///         amount — preserving spot. The proportional TOKEN is held as
    ///         per-position loanReserveToken (will flow back to LP on repay
    ///         or be absorbed by LP on liquidation).
    function borrow(uint256 collateralIn)
        external
        nonReentrant
        returns (uint256 debtETH, uint256 netToUser)
    {
        if (!poolInitialized) revert PoolNotInitializedErr();
        if (block.number <= lastSwapBlock) revert SwapInSameBlock();
        if (collateralIn == 0) revert CollateralBelowMin();
        if (realETH == 0 || realToken == 0) revert InsufficientLiquidity();

        require(token.transferFrom(msg.sender, address(this), collateralIn), "PullFail");

        // Value the collateral at current pool spot
        uint256 collateralValueETH = collateralIn * realETH / realToken;
        debtETH = collateralValueETH * LTV_BPS / 10_000;
        if (debtETH < MIN_DEBT) revert DebtBelowMin();
        if (debtETH >= realETH) revert InsufficientLiquidity();

        // Proportional withdraw — keeps spot constant
        uint256 tokenFromLP = debtETH * realToken / realETH;

        uint128 lqToRemove = _liquidityForAmounts(debtETH, tokenFromLP);
        if (lqToRemove == 0 || lqToRemove > liquidity) revert InsufficientLiquidity();

        bytes memory ret = poolManager.unlock(abi.encode(
            Action.BORROW,
            abi.encode(lqToRemove, debtETH, tokenFromLP)
        ));
        (uint256 actualETH, uint256 actualToken, uint256 lpCut) =
            abi.decode(ret, (uint256, uint256, uint256));
        // V4 may return slightly less due to rounding; trust the deltas
        if (actualETH < debtETH) debtETH = actualETH;

        // Origination fee split — recomputed from actualETH so all numbers
        // round-trip even when V4 returns slightly less than requested. The
        // handler already donated `lpCut` to the LP via PoolManager.donate.
        uint256 origFee     = debtETH * ORIG_FEE_BPS / LTV_BPS;
        uint256 protocolCut = origFee - lpCut;
        netToUser           = debtETH - origFee;

        liquidity -= lqToRemove;
        // realETH net movement: pulled debtETH out, donated lpCut back.
        realETH   -= (debtETH - lpCut);
        realToken -= actualToken;

        Position storage p = positions[msg.sender];
        p.collateral       += collateralIn;
        p.debt             += debtETH;
        p.loanReserveToken += actualToken;
        p.openedAtBlock     = uint64(block.number);

        totalDebt              += debtETH;
        totalCollateralLocked  += collateralIn;
        totalLoanReserveToken  += actualToken;

        // protocolCut → FeeCollector (LOOP holders revenue).
        // netToUser → borrower's wallet.
        (bool sf,) = feeCollector.call{value: protocolCut}("");
        if (!sf) revert EthTransferFailed();
        (bool su,) = msg.sender.call{value: netToUser}("");
        if (!su) revert EthTransferFailed();

        emit Borrowed(msg.sender, collateralIn, debtETH, netToUser, origFee);
    }

    // ─── Repay ──────────────────────────────────────────────────────────────

    /// @notice Repay debt — either full close or partial.
    ///         · Full close: msg.value must equal debt + POSITION_CLOSE_FEE.
    ///                       Fee routes to FeeCollector, debt amount refills LP.
    ///         · Partial:    msg.value must leave at least MIN_DEBT remaining,
    ///                       no fee. Caller can keep paying down via repeat calls.
    function repay() external payable nonReentrant {
        Position storage p = positions[msg.sender];
        if (p.debt == 0) revert NoOpenPosition();
        if (block.number < p.openedAtBlock + REPAY_COOLDOWN_BLOCKS) revert CooldownActive();

        uint256 sent = msg.value;
        if (sent == 0) revert RepayAmountMismatch();

        uint256 amount;       // debt actually being paid down
        uint256 closeFee = 0;
        bool full;

        if (sent == p.debt + POSITION_CLOSE_FEE) {
            // Full close: debt + flat fee
            amount   = p.debt;
            closeFee = POSITION_CLOSE_FEE;
            full     = true;
        } else if (sent <= p.debt && (p.debt - sent) >= MIN_DEBT) {
            // Partial: leaves at least MIN_DEBT remaining
            amount = sent;
            full   = false;
        } else {
            revert InvalidRepayAmount();
        }

        uint256 collateralReturn = full ? p.collateral : p.collateral * amount / p.debt;
        uint256 tokenRefill      = full ? p.loanReserveToken : p.loanReserveToken * amount / p.debt;

        uint128 lqAdded = _liquidityForAmounts(amount, tokenRefill);

        bytes memory ret = poolManager.unlock(abi.encode(
            Action.REPAY,
            abi.encode(lqAdded, amount, tokenRefill)
        ));
        (uint256 actualETH, uint256 actualToken) = abi.decode(ret, (uint256, uint256));

        liquidity += lqAdded;
        realETH   += actualETH;
        realToken += actualToken;

        p.debt              -= amount;
        p.collateral        -= collateralReturn;
        p.loanReserveToken  -= tokenRefill;
        if (full) delete positions[msg.sender];

        totalDebt              -= amount;
        totalCollateralLocked  -= collateralReturn;
        totalLoanReserveToken  -= tokenRefill;

        require(token.transfer(msg.sender, collateralReturn), "ReturnFailed");

        if (closeFee > 0) {
            (bool sf,) = feeCollector.call{value: closeFee}("");
            if (!sf) revert EthTransferFailed();
        }

        emit Repaid(msg.sender, amount, collateralReturn, full);
    }

    // ─── Liquidate ──────────────────────────────────────────────────────────

    /// @notice Permissionless liquidation when collateral × spot < 1.5 × debt.
    ///         Bot pays the full debt in ETH, receives collateral TOKEN priced
    ///         at spot × (1 - 2.5 %) — i.e. 2.5 % more TOKEN than a spot
    ///         purchase. Residual collateral (anything left after bot's payout)
    ///         and the loanReserveToken are refilled into the LP, preserving
    ///         the self-healing property: pool depth grows after every liq.
    ///         No oracle — pool's own spot is the price (same-block lockout
    ///         closes manipulation).
    function liquidate(address victim) external payable nonReentrant {
        // Mirrors V2: no `lastSwapBlock` check (bot must react to spot drops),
        // but hard-cap one liquidation per block (prevents atomic batching)
        // AND register the block so beforeSwap blocks public swaps in this
        // block (kills cross-pool buyback / bundled exploit).
        if (block.number <= lastLiquidationBlock) revert OneLiquidationPerBlock();

        Position storage p = positions[victim];
        if (p.debt == 0) revert NoOpenPosition();

        // Underwater check at current pool spot
        uint256 collateralValueETH = p.collateral * realETH / realToken;
        if (collateralValueETH * 10_000 >= p.debt * LIQUIDATION_THRESHOLD_BPS) revert NotUnderwater();

        uint256 debtAmount = p.debt;
        if (msg.value < debtAmount) revert RepayAmountMismatch();

        // Bot receives `debt`-worth of TOKEN at 2.5 % discount.
        //   debt-equivalent TOKEN at spot   = debt × realToken / realETH
        //   with 2.5 % bonus                = × (10_000 + 250) / 10_000
        // Cap at collateral for the bad-debt edge (HF < 1.026).
        uint256 tokenToBot =
            (debtAmount * realToken * (10_000 + LIQUIDATION_DISCOUNT_BPS))
            / (realETH * 10_000);
        if (tokenToBot > p.collateral) tokenToBot = p.collateral;

        uint256 residualToken = p.collateral - tokenToBot;

        // LP refill: full debt ETH + loanReserveToken + residual collateral.
        // V4 modifyLiquidity will use only the proportional amounts needed at
        // the current pool ratio; any side excess is routed to FC below.
        uint256 refillETH   = debtAmount;
        uint256 refillToken = p.loanReserveToken + residualToken;
        // Register the liquidation block BEFORE the external call. Any swap
        // inside the unlock callback (none today, but defensive) or in the
        // same block from external sender will hit BlockedByLiquidation.
        lastLiquidationBlock = uint64(block.number);

        uint128 lqAdded     = _liquidityForAmounts(refillETH, refillToken);

        bytes memory ret = poolManager.unlock(abi.encode(
            Action.LIQUIDATE,
            abi.encode(lqAdded, refillETH, refillToken)
        ));
        (uint256 actualETH, uint256 actualToken) = abi.decode(ret, (uint256, uint256));

        liquidity += lqAdded;
        realETH   += actualETH;
        realToken += actualToken;

        // Side that didn't fully fit the current ratio → FeeCollector. After
        // a price drop the ETH side is usually the surplus (LP wants more
        // TOKEN per ETH at the new spot).
        if (actualETH < refillETH) {
            uint256 excessETH = refillETH - actualETH;
            (bool se,) = feeCollector.call{value: excessETH}("");
            if (!se) revert EthTransferFailed();
        }
        if (actualToken < refillToken) {
            uint256 excessToken = refillToken - actualToken;
            require(token.transfer(feeCollector, excessToken), "ExcessXfer");
        }

        // Snapshot before delete for the event
        uint256 collateral = p.collateral;
        uint256 loanReserve = p.loanReserveToken;
        delete positions[victim];
        totalDebt              -= debtAmount;
        totalCollateralLocked  -= collateral;
        totalLoanReserveToken  -= loanReserve;

        // Pay bot in TOKEN
        require(token.transfer(msg.sender, tokenToBot), "BotPayout");

        // Refund any overpaid msg.value
        if (msg.value > debtAmount) {
            uint256 refund = msg.value - debtAmount;
            (bool sr,) = msg.sender.call{value: refund}("");
            if (!sr) revert EthTransferFailed();
        }

        emit Liquidated(victim, msg.sender, collateral, debtAmount, tokenToBot, residualToken);
    }

    // ─── Hook callbacks ─────────────────────────────────────────────────────

    function beforeInitialize(address sender, PoolKey calldata key, uint160)
        external
        view
        returns (bytes4)
    {
        if (sender != address(this)) revert NotOwner();
        if (
            Currency.unwrap(key.currency0) != address(0)
            || Currency.unwrap(key.currency1) != address(token)
            || address(key.hooks) != address(this)
        ) revert InvalidPoolKey();
        return IHooks.beforeInitialize.selector;
    }

    function afterInitialize(address, PoolKey calldata, uint160, int24)
        external
        pure
        returns (bytes4)
    {
        return IHooks.afterInitialize.selector;
    }

    /// @notice 3rd-party LP guard: only the hook itself may modify liquidity
    ///         (via deposit/withdraw/borrow/repay/liquidate). All external
    ///         attempts revert.
    function beforeAddLiquidity(address sender, PoolKey calldata, ModifyLiquidityParams calldata, bytes calldata)
        external
        view
        returns (bytes4)
    {
        if (sender != address(this)) revert UnauthorizedLP();
        return IHooks.beforeAddLiquidity.selector;
    }

    function beforeRemoveLiquidity(address sender, PoolKey calldata, ModifyLiquidityParams calldata, bytes calldata)
        external
        view
        returns (bytes4)
    {
        if (sender != address(this)) revert UnauthorizedLP();
        return IHooks.beforeRemoveLiquidity.selector;
    }

    /// @notice Skim 1 % of the input on every swap. For ETH→TOKEN (zeroForOne),
    ///         we take 1 % of msg.value ETH; for TOKEN→ETH, 1 % of the output
    ///         ETH is taken in afterSwap. Native ETH lives in PoolManager as
    ///         currency0, so on buys we mint an ERC-6909 claim equal to the
    ///         fee and redeem it later (matches V2 pattern). For simplicity in
    ///         v1, route 1 % directly to FeeCollector via take/transfer.
    function beforeSwap(address sender, PoolKey calldata key, SwapParams calldata params, bytes calldata)
        external
        onlyPoolManager
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        // Hook-internal swaps bypass the fee (none in v1, but defensive).
        if (sender == address(this)) {
            return (IHooks.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
        }
        // Reject external swaps in any block that has had a liquidation —
        // mirrors V2's cross-pool buyback defense. Closes the bundled attack
        // pattern: dump → liq → buy-back at crashed spot in same block.
        if (block.number == lastLiquidationBlock) revert BlockedByLiquidation();
        // Only BUYs (ETH-in) skimmed in beforeSwap — SELLs in afterSwap so we
        // know the ETH-out amount.
        if (!params.zeroForOne || params.amountSpecified >= 0) {
            return (IHooks.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
        }

        uint256 amountIn = uint256(-params.amountSpecified);
        uint256 fee      = amountIn * PROTOCOL_SWAP_FEE_BPS / 10_000;
        if (fee == 0) {
            return (IHooks.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
        }

        // Forward the protocol cut to FeeCollector. PM has ETH from the user's
        // settle leg; the BeforeSwapDelta makes the user pay `fee` extra so
        // PM's accounting still balances at unlock end.
        poolManager.take(key.currency0, feeCollector, fee);
        emit Swapped(tx.origin, true, amountIn, fee);
        return (
            IHooks.beforeSwap.selector,
            toBeforeSwapDelta(int128(int256(fee)), 0),
            0
        );
    }

    // Unused hook callbacks — IHooks interface requires all 14 selectors even
    // if our Hooks.Permissions struct says false (the address bits select
    // which the PoolManager actually calls). These stubs revert defensively.
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

    /// @notice Record the swap block for same-block lockout. For SELLs, also
    ///         skim 1 % of the ETH output as fee.
    function afterSwap(address sender, PoolKey calldata key, SwapParams calldata params, BalanceDelta delta, bytes calldata)
        external
        onlyPoolManager
        returns (bytes4, int128)
    {
        lastSwapBlock = uint64(block.number);

        // Sync realETH/realToken from V4's current state. Swaps shift sqrtP
        // and thus the LP's internal composition; we re-derive the mirrors
        // from (sqrtP, liquidity) so subsequent borrow / liquidate / view
        // calls see fresh numbers. Hook-internal swaps bypass — there are
        // none currently but defensive.
        if (sender != address(this) && liquidity > 0) {
            (uint160 sqrtP_,,,) = poolManager.getSlot0(_poolId());
            (realETH, realToken) = LiquidityAmounts.getAmountsForLiquidity(
                sqrtP_,
                TickMath.getSqrtPriceAtTick(tickLower),
                TickMath.getSqrtPriceAtTick(tickUpper),
                liquidity
            );
        }

        if (sender == address(this))                return (IHooks.afterSwap.selector, 0);
        if (params.zeroForOne)                      return (IHooks.afterSwap.selector, 0);
        if (params.amountSpecified >= 0)            return (IHooks.afterSwap.selector, 0);

        int128 a0 = delta.amount0();                 // ETH out (unspecified)
        if (a0 <= 0) return (IHooks.afterSwap.selector, 0);

        uint256 ethOut = uint256(uint128(a0));
        uint256 fee    = ethOut * PROTOCOL_SWAP_FEE_BPS / 10_000;
        if (fee == 0)  return (IHooks.afterSwap.selector, 0);

        poolManager.take(key.currency0, feeCollector, fee);
        emit Swapped(tx.origin, false, uint256(-params.amountSpecified), fee);
        return (IHooks.afterSwap.selector, int128(int256(fee)));
    }

    // ─── Unlock callback ────────────────────────────────────────────────────
    enum Action { LP_ADD, LP_REMOVE, BORROW, REPAY, LIQUIDATE }

    function unlockCallback(bytes calldata data) external onlyPoolManager returns (bytes memory) {
        (Action action, bytes memory payload) = abi.decode(data, (Action, bytes));

        if (action == Action.LP_ADD)       return _handleLpAdd(payload);
        if (action == Action.LP_REMOVE)    return _handleLpRemove(payload);
        if (action == Action.BORROW)       return _handleBorrow(payload);
        if (action == Action.REPAY)        return _handleRepay(payload);
        if (action == Action.LIQUIDATE)    return _handleLiquidate(payload);
        revert InvalidAction();
    }

    function _handleLpAdd(bytes memory payload) internal returns (bytes memory) {
        (uint256 ethIn, uint256 tokenIn) = abi.decode(payload, (uint256, uint256));

        uint128 lqAdded = _liquidityForAmounts(ethIn, tokenIn);

        (BalanceDelta delta,) = poolManager.modifyLiquidity(
            poolKey,
            ModifyLiquidityParams({
                tickLower:      tickLower,
                tickUpper:      tickUpper,
                liquidityDelta: int256(uint256(lqAdded)),
                salt:           bytes32(0)
            }),
            ""
        );

        // Settle both currencies (we owe ETH and TOKEN to PM)
        int128 a0 = delta.amount0();
        int128 a1 = delta.amount1();
        require(a0 <= 0 && a1 <= 0, "AddDeltaSign");

        if (a0 < 0) {
            uint256 ethOwed = uint256(uint128(-a0));
            poolManager.sync(CurrencyLibrary.ADDRESS_ZERO);
            poolManager.settle{value: ethOwed}();
        }
        if (a1 < 0) {
            uint256 tokenOwed = uint256(uint128(-a1));
            poolManager.sync(poolKey.currency1);
            require(token.transfer(address(poolManager), tokenOwed), "TokXfer");
            poolManager.settle();
        }
        return abi.encode(lqAdded);
    }

    function _handleLpRemove(bytes memory payload) internal returns (bytes memory) {
        (uint128 lqToBurn, , , address recipient) =
            abi.decode(payload, (uint128, uint256, uint256, address));

        (BalanceDelta delta,) = poolManager.modifyLiquidity(
            poolKey,
            ModifyLiquidityParams({
                tickLower:      tickLower,
                tickUpper:      tickUpper,
                liquidityDelta: -int256(uint256(lqToBurn)),
                salt:           bytes32(0)
            }),
            ""
        );
        int128 a0 = delta.amount0();
        int128 a1 = delta.amount1();
        require(a0 >= 0 && a1 >= 0, "RemoveDeltaSign");

        // Use the ACTUAL amounts V4 returned (handles rounding precisely).
        uint256 ethGot   = uint256(uint128(a0));
        uint256 tokenGot = uint256(uint128(a1));

        if (ethGot > 0) {
            poolManager.take(CurrencyLibrary.ADDRESS_ZERO, recipient, ethGot);
        }
        if (tokenGot > 0) {
            poolManager.take(poolKey.currency1, recipient, tokenGot);
        }
        return abi.encode(ethGot, tokenGot);
    }

    function _handleBorrow(bytes memory payload) internal returns (bytes memory) {
        (uint128 lqToRemove, uint256 ethTarget, uint256 tokenTarget) =
            abi.decode(payload, (uint128, uint256, uint256));

        (BalanceDelta delta,) = poolManager.modifyLiquidity(
            poolKey,
            ModifyLiquidityParams({
                tickLower:      tickLower,
                tickUpper:      tickUpper,
                liquidityDelta: -int256(uint256(lqToRemove)),
                salt:           bytes32(0)
            }),
            ""
        );
        int128 a0 = delta.amount0();
        int128 a1 = delta.amount1();
        require(a0 > 0 && a1 > 0, "BorrowDeltaSign");

        // V4 may return MORE than target due to LP fees accrued since last
        // touch. We must TAKE everything (else PM accounting drifts and
        // unlock reverts CurrencyNotSettled). Route any surplus over the
        // borrow target to FeeCollector as protocol revenue.
        uint256 grossETH   = uint256(uint128(a0));
        uint256 grossToken = uint256(uint128(a1));
        poolManager.take(CurrencyLibrary.ADDRESS_ZERO, address(this), grossETH);
        poolManager.take(poolKey.currency1, address(this), grossToken);

        uint256 actualETH   = grossETH   > ethTarget   ? ethTarget   : grossETH;
        uint256 actualToken = grossToken > tokenTarget ? tokenTarget : grossToken;

        // Forward V4-fee surplus to FC
        if (grossETH > actualETH) {
            uint256 excess = grossETH - actualETH;
            (bool s,) = feeCollector.call{value: excess}("");
            if (!s) revert EthTransferFailed();
        }
        if (grossToken > actualToken) {
            uint256 excess = grossToken - actualToken;
            require(token.transfer(feeCollector, excess), "ExcessXfer");
        }

        // Donate the LP slice of the origination fee back to the position.
        // Computed from `actualETH` (not pre-unlock target) so the math
        // round-trips even when V4 returns slightly less than requested.
        // V4 credits the donation to the LP's fee accumulators; LPs collect
        // on their next modifyLiquidity (withdraw / borrow / repay refill).
        // No new shares minted — share value increases for everyone pro-rata.
        uint256 origFee     = actualETH * ORIG_FEE_BPS / LTV_BPS;
        uint256 protocolCut = origFee * PROTOCOL_FEE_BPS / 10_000;
        uint256 lpDonateETH = origFee - protocolCut;
        if (lpDonateETH > 0) {
            poolManager.donate(poolKey, lpDonateETH, 0, "");
            poolManager.sync(CurrencyLibrary.ADDRESS_ZERO);
            poolManager.settle{value: lpDonateETH}();
        }

        return abi.encode(actualETH, actualToken, lpDonateETH);
    }

    function _handleRepay(bytes memory payload) internal returns (bytes memory) {
        (uint128 lqAdded, uint256 ethIn, uint256 tokenIn) =
            abi.decode(payload, (uint128, uint256, uint256));

        (BalanceDelta delta,) = poolManager.modifyLiquidity(
            poolKey,
            ModifyLiquidityParams({
                tickLower:      tickLower,
                tickUpper:      tickUpper,
                liquidityDelta: int256(uint256(lqAdded)),
                salt:           bytes32(0)
            }),
            ""
        );
        // V4's callerDelta nets accrued LP fees against the add cost. So even
        // a pure `+L` modifyLiquidity can return mixed-sign deltas: negative
        // = we owe principal, positive = V4 returns previously-earned swap fees.
        // Handle both directions: settle what we owe, take what V4 offers.
        int128 a0 = delta.amount0();
        int128 a1 = delta.amount1();

        uint256 ethOwed   = a0 < 0 ? uint256(uint128(-a0)) : 0;
        uint256 tokenOwed = a1 < 0 ? uint256(uint128(-a1)) : 0;
        uint256 ethRecv   = a0 > 0 ? uint256(uint128(a0))  : 0;
        uint256 tokenRecv = a1 > 0 ? uint256(uint128(a1))  : 0;

        if (ethOwed > ethIn) ethOwed = ethIn;
        if (tokenOwed > tokenIn) tokenOwed = tokenIn;

        if (ethOwed > 0) {
            poolManager.sync(CurrencyLibrary.ADDRESS_ZERO);
            poolManager.settle{value: ethOwed}();
        }
        if (tokenOwed > 0) {
            poolManager.sync(poolKey.currency1);
            require(token.transfer(address(poolManager), tokenOwed), "TokXfer");
            poolManager.settle();
        }
        // Accrued V4 fees that came back as positive deltas → route to FC
        // (LP yield boost is handled separately via the auto-compound on
        // subsequent modifyLiquidity calls; explicit harvest here is FC revenue.)
        if (ethRecv > 0) {
            poolManager.take(CurrencyLibrary.ADDRESS_ZERO, feeCollector, ethRecv);
        }
        if (tokenRecv > 0) {
            poolManager.take(poolKey.currency1, feeCollector, tokenRecv);
        }
        return abi.encode(ethOwed, tokenOwed);
    }

    function _handleLiquidate(bytes memory payload) internal returns (bytes memory) {
        // Same path as repay (refill LP), just with different numbers.
        return _handleRepay(payload);
    }

    // ─── Views ──────────────────────────────────────────────────────────────

    function getPosition(address user) external view returns (Position memory) {
        return positions[user];
    }

    function spotPriceX18() external view returns (uint256) {
        if (realToken == 0) return 0;
        return realETH * 1e18 / realToken;  // ETH per TOKEN (1e18 scale)
    }

    function isUnderwater(address user) external view returns (bool) {
        Position memory p = positions[user];
        if (p.debt == 0) return false;
        uint256 collValue = p.collateral * realETH / realToken;
        return collValue * 10_000 < p.debt * LIQUIDATION_THRESHOLD_BPS;
    }

    /// @notice Quote a deposit: how many shares would `ethIn` mint?
    function quoteDeposit(uint256 ethIn) external view returns (uint256 sharesOut, uint256 tokenRequired) {
        if (totalSupply() == 0) return (0, 0);  // first depositor — open-ended
        tokenRequired = ethIn * realToken / realETH;
        sharesOut     = ethIn * totalSupply() / realETH;
    }

    /// @notice Quote a borrow: how much ETH would `collateralIn` get?
    function quoteBorrow(uint256 collateralIn)
        external
        view
        returns (uint256 debtETH, uint256 netToUser, bool feasible)
    {
        if (realETH == 0 || realToken == 0) return (0, 0, false);
        uint256 collateralValueETH = collateralIn * realETH / realToken;
        debtETH = collateralValueETH * LTV_BPS / 10_000;
        if (debtETH < MIN_DEBT) return (debtETH, 0, false);
        if (debtETH >= realETH) return (debtETH, 0, false);
        uint256 origFee = debtETH * ORIG_FEE_BPS / LTV_BPS;
        netToUser = debtETH - origFee;
        feasible = true;
    }

    // ─── Aggregated views (one RPC = full UI state) ─────────────────────────

    /// @notice Snapshot of every dynamic field the UI needs in one call. Pass
    ///         `user = address(0)` to read pool state only without the user
    ///         block (saves a few token external-call gas).
    struct MarketState {
        // Pool state ────────────────────────────────────────
        uint256 realETH;
        uint256 realToken;
        uint128 liquidity;
        uint256 totalShares;
        uint256 totalDebt;
        uint256 totalCollateral;
        uint256 totalLoanReserveToken;
        uint256 spotX18;              // ETH per TOKEN, 1e18 scale (0 if no LP)
        uint160 sqrtPriceX96;         // raw V4 price
        uint64  lastSwapBlock;
        uint64  lastLiquidationBlock;
        bool    poolInitialized;

        // User state — zero if user == address(0) ────────────
        uint256 userEthBalance;
        uint256 userTokenBalance;
        uint256 userTokenAllowance;   // user → hook for deposits/borrow
        uint256 userShareBalance;
        uint256 userCollateral;
        uint256 userDebt;
        uint256 userLoanReserveToken;
        uint64  userOpenedAtBlock;
        bool    userIsUnderwater;
    }

    function getMarketState(address user) external view returns (MarketState memory s) {
        s.realETH               = realETH;
        s.realToken             = realToken;
        s.liquidity             = liquidity;
        s.totalShares           = totalSupply();
        s.totalDebt             = totalDebt;
        s.totalCollateral       = totalCollateralLocked;
        s.totalLoanReserveToken = totalLoanReserveToken;
        s.lastSwapBlock         = lastSwapBlock;
        s.lastLiquidationBlock  = lastLiquidationBlock;
        s.poolInitialized       = poolInitialized;
        if (realToken > 0) s.spotX18 = realETH * 1e18 / realToken;
        if (poolInitialized) {
            (s.sqrtPriceX96,,,) = poolManager.getSlot0(_poolId());
        }

        if (user != address(0)) {
            s.userEthBalance       = user.balance;
            s.userTokenBalance     = token.balanceOf(user);
            s.userTokenAllowance   = token.allowance(user, address(this));
            s.userShareBalance     = balanceOf(user);
            Position memory p = positions[user];
            s.userCollateral       = p.collateral;
            s.userDebt             = p.debt;
            s.userLoanReserveToken = p.loanReserveToken;
            s.userOpenedAtBlock    = p.openedAtBlock;
            if (p.debt > 0 && realToken > 0) {
                uint256 collValue = p.collateral * realETH / realToken;
                s.userIsUnderwater = collValue * 10_000 < p.debt * LIQUIDATION_THRESHOLD_BPS;
            }
        }
    }

    /// @notice Every protocol constant in one call. Frontends cache this on
    ///         mount; never changes for a given deployment.
    struct ProtocolConstants {
        uint256 ltvBps;
        uint256 origFeeBps;
        uint24  lpSwapFeePips;
        uint256 protocolSwapFeeBps;
        uint256 liquidationThresholdBps;
        uint256 liquidationDiscountBps;
        uint256 repayCooldownBlocks;
        uint256 minDebt;
        uint256 positionCloseFee;
        uint256 minimumShares;
    }

    function getConstants() external pure returns (ProtocolConstants memory c) {
        c.ltvBps                  = LTV_BPS;
        c.origFeeBps              = ORIG_FEE_BPS;
        c.lpSwapFeePips           = LP_SWAP_FEE_PIPS;
        c.protocolSwapFeeBps      = PROTOCOL_SWAP_FEE_BPS;
        c.liquidationThresholdBps = LIQUIDATION_THRESHOLD_BPS;
        c.liquidationDiscountBps  = LIQUIDATION_DISCOUNT_BPS;
        c.repayCooldownBlocks     = REPAY_COOLDOWN_BLOCKS;
        c.minDebt                 = MIN_DEBT;
        c.positionCloseFee        = POSITION_CLOSE_FEE;
        c.minimumShares           = MINIMUM_SHARES;
    }

    /// @notice Withdraw quote: burning `sharesIn` would return what ETH/TOKEN
    ///         at current pool composition? Lets the UI render an accurate
    ///         "you receive" block without round-tripping math.
    function quoteWithdraw(uint256 sharesIn) external view returns (uint256 ethOut, uint256 tokenOut) {
        uint256 supply = totalSupply();
        if (supply == 0 || sharesIn == 0) return (0, 0);
        ethOut   = realETH   * sharesIn / supply;
        tokenOut = realToken * sharesIn / supply;
    }

    /// @notice Utility ratio (1e4 scale): pool ETH lent out / total ETH.
    ///         0 = no borrows, 10_000 = fully lent. UI uses this for the
    ///         "withdraw composition" warning.
    function utilizationBps() external view returns (uint256) {
        uint256 ethSide = realETH;
        uint256 borrowed = totalDebt;
        if (ethSide + borrowed == 0) return 0;
        return borrowed * 10_000 / (ethSide + borrowed);
    }

    // ─── Internal helpers ───────────────────────────────────────────────────

    function _poolId() internal view returns (PoolId) {
        return PoolIdLibrary.toId(poolKey);
    }

    function _liquidityForAmounts(uint256 ethAmt, uint256 tokenAmt) internal view returns (uint128) {
        (uint160 sqrtP,,,) = poolManager.getSlot0(_poolId());
        uint160 sqrtLow  = TickMath.getSqrtPriceAtTick(tickLower);
        uint160 sqrtHigh = TickMath.getSqrtPriceAtTick(tickUpper);
        return LiquidityAmounts.getLiquidityForAmounts(sqrtP, sqrtLow, sqrtHigh, ethAmt, tokenAmt);
    }

    function _sqrt(uint256 x) internal pure returns (uint256 y) {
        if (x == 0) return 0;
        uint256 z = (x + 1) / 2;
        y = x;
        while (z < y) { y = z; z = (x / z + z) / 2; }
    }

    // Accept ETH refunds from PoolManager
    receive() external payable {}
}

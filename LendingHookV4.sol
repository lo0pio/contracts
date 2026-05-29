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
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title  LendingHookV4 — community-LP lending AMM for existing tokens
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
contract LendingHookV4 is IHooks, IUnlockCallback, ERC20 {
    using StateLibrary for IPoolManager;
    using SafeERC20 for IERC20;

    // ─── Constants ──────────────────────────────────────────────────────────
    uint256 public constant LTV_BPS                   = 4000;       // 40 %
    uint256 public constant ORIG_FEE_BPS              = 100;        // 1 % of debt

    /// @notice System-wide cap on `totalDebt` as a fraction of `realETH`.
    ///         1000-run pump-borrow simulation showed 0 % profitable attacks
    ///         across every cap value tested (LTV + slippage already make the
    ///         attack net-negative); cap mainly bounds the BAD-DEBT
    ///         accumulation rate when multiple positions go underwater
    ///         simultaneously. Selected 70 % — Aave-style utilization headroom
    ///         while keeping worst-case bad debt below ~15 % of pool depth.
    uint256 public constant UTILIZATION_CAP_BPS       = 7000;       // 70 %

    /// @notice Per-position cap as a fraction of `realETH`. Applies to the
    ///         position's *total* debt after this borrow (so incremental
    ///         borrows accumulate against the cap). Plan default: 100 %, i.e.
    ///         the system cap is the binding constraint at launch — kept here
    ///         as defense-in-depth for any future tuning via redeploy.
    uint256 public constant MAX_BORROW_BPS            = 10_000;     // 100 %

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

    /// @notice Interest rate parameters. Rate is LOCKED at borrow time from
    ///         the current utilization curve; future rate changes do not
    ///         affect existing positions (predictable cost for borrowers).
    ///         Curve: rate = base + util*slope, with a kink at OPTIMAL_UTIL
    ///         where slope becomes JUMP. Encourages LP yield growth while
    ///         keeping rates flat in the healthy zone.
    uint256 public constant BASE_RATE_BPS             = 250;        // 2.5 % APR base
    uint256 public constant OPTIMAL_UTIL_BPS          = 5_000;      // 50 % kink point
    uint256 public constant SLOPE_NORMAL_BPS          = 2_000;      // +20 % per 100 % util in normal zone
    uint256 public constant SLOPE_JUMP_BPS            = 25_000;     // +250 % per 100 % util above kink

    /// @notice Hard ceiling on the borrow rate the curve can return. Belt-and-
    ///         suspenders with `UTILIZATION_CAP_BPS` — today's 70 % util cap
    ///         alone keeps the curve at 62.5 % APR, but if a future redeploy
    ///         loosens that cap, this hard ceiling caps `getDebt`'s interest
    ///         multiplier and prevents overflow on long-dated positions.
    uint256 public constant MAX_RATE_BPS              = 10_000;     // 100 % APR

    /// @notice Avg block time used for interest accrual (post-merge 12 s).
    uint256 public constant SECS_PER_BLOCK            = 12;
    uint256 public constant SECS_PER_YEAR             = 365 days;

    /// @notice Each borrow call must produce at least MIN_DEBT new debt. Plus
    ///         every partial repay must leave at least MIN_DEBT remaining (or
    ///         go to zero). Keeps dust positions out of state.
    uint256 public constant MIN_DEBT                  = 0.1 ether;

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

    /// @notice Blocks of swap-quiet required before `_safeSpotX18()` is allowed
    ///         to fall back to the live pool ratio. Inside this window the
    ///         older `prevSnap` is used instead — so an attacker who pumps
    ///         spot in block N can NOT exploit `liquidate` / `borrow` in any
    ///         of blocks N, N+1, N+2. To bypass they would need to hold the
    ///         manipulation for 3 consecutive blocks against organic arbitrage
    ///         — economically unrealistic at lo0p pool depths.
    uint64 public constant SAFE_LAG = 2;

    /// @notice Blocks that LP shares must be held before withdraw is allowed.
    ///         Defends against JIT-LP MEV sandwich around `borrow` / `repay`
    ///         donates — a bot that deposits, triggers a donate-paying op,
    ///         and withdraws in the same block (or +1) would capture LP-share
    ///         yield that should accrue to long-term LPs. Resets on every
    ///         mint AND inbound transfer (ERC20 `_update` hook), so the
    ///         attacker can't escape the cooldown by transferring shares.
    uint64 public constant LP_COOLDOWN_BLOCKS = 2;

    // ─── Errors ─────────────────────────────────────────────────────────────
    error NotDeployer();
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
    error SqrtPriceOutOfRange();
    error CollateralBelowMin();
    error DebtSlippage();
    error TokenTransferBalanceMismatch();
    error LPCooldownActive();
    error DebtBelowMin();
    error InvalidRepayAmount();
    error NoOpenPosition();
    error CooldownActive();
    error RepayAmountMismatch();
    error NotUnderwater();
    error InsufficientLiquidity();
    error UtilizationCapExceeded();
    error MaxBorrowExceeded();
    error RatioMismatch();
    error MinSharesNotMet();
    error SlippageExceeded();
    error BlockedByLiquidation();

    // ─── Immutables ─────────────────────────────────────────────────────────
    /// @notice Mainnet Uniswap V4 PoolManager — deterministic CREATE2 address,
    ///         identical for the life of v4. Hardcoded so deploys can't pass
    ///         the wrong PoolManager. Test environments must `vm.etch` real
    ///         PoolManager bytecode to this address.
    IPoolManager   public constant  poolManager =
        IPoolManager(0x000000000004444c5dc75cB358380D2e3dE08A90);
    IERC20         public immutable token;          // e.g. SATO
    /// @notice lo0p protocol fee sink — receives swap fees + origination fees
    ///         across every market. Hardcoded so all V4 markets converge to
    ///         the same revenue contract; no per-market typo risk.
    address        public constant  feeCollector = 0x6beAc0dd77044A9B6D290efC8Fb95D1fd670a415;
    /// @notice Lone privileged role on the deployed hook. Set to `msg.sender`
    ///         at construction (typically the factory). Can ONLY call
    ///         `setDeployer` to hand the role over (or burn it by passing
    ///         address(0)). No other function in this contract is gated by it
    ///         — `initializePool` is intentionally permissionless and protected
    ///         instead by `beforeInitialize`'s PoolKey canonicalization +
    ///         `PoolAlreadyInitialized` one-shot guard.
    address public deployer;
    int24          public immutable tickLower;      // full-range, spacing-aligned
    int24          public immutable tickUpper;

    // ─── State ──────────────────────────────────────────────────────────────
    PoolKey public poolKey;
    bool    public poolInitialized;

    /// @notice LP-side state. `realETH` and `realToken` mirror the V4 position
    ///         the hook holds, MINUS amounts currently lent out to borrowers
    ///         (those live in per-position loanReserveToken). The relation is:
    ///             v4PositionPrincipal (ETH)   = realETH + totalDebt
    ///             v4PositionPrincipal (TOKEN) = realToken + totalLoanReserveToken
    ///         The mirror tracks PRINCIPAL only. Accrued V4 LP swap fees live
    ///         in the position's fee accumulator and are explicitly re-donated
    ///         to the position by each borrow/repay/liquidate handler (see
    ///         `_handleLpAdd` / `_handleRepay` / `_handleBorrow`) so LPs realize
    ///         them as share-value growth on withdraw. `afterSwap`'s re-sync
    ///         of (realETH, realToken) from `getAmountsForLiquidity` is also
    ///         principal-only — fees stay off-mirror by design.
    uint256 public realETH;
    uint256 public realToken;
    uint128 public liquidity;          // current V4 position liquidity
    // Share token state lives on the inherited ERC20 (balanceOf / totalSupply).
    // The hook itself IS the LP share token — e.g. "lo0pED SATO/ETH".
    // Transferable, composable with the rest of DeFi.

    /// @notice Per-user lending position. One position per user (additive
    ///         borrows extend it; partial repay shrinks it pro-rata).
    /// @dev    `debt` here is the PRINCIPAL — the ETH owed at the moment
    ///         the position was last anchored (borrow or partial repay).
    ///         Interest accrues on top at `rateBps` since `openedAtBlock`;
    ///         use `getDebt(user)` for the full effective amount owed.
    struct Position {
        uint256 collateral;        // locked TOKEN
        uint256 debt;              // PRINCIPAL ETH (accrues interest at rateBps)
        uint256 loanReserveToken;  // TOKEN proportionally pulled from LP at borrow time
        uint64  openedAtBlock;
        uint64  rateBps;           // interest rate locked at borrow time (weighted-avg on incremental)
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

    /// @notice Block of the most recent liquidation. External swaps, borrows
    ///         and withdraws in the same block revert (`BlockedByLiquidation`),
    ///         neutralising the cross-pool buyback leg of the atomic-bundle
    ///         MEV attack. Multiple liquidations within a single block are
    ///         permitted — safeSpot lag + proportional refill prevent any
    ///         drift-based exploit across consecutive liqs.
    uint64 public lastLiquidationBlock;

    /// @notice Block of the most recent share receipt (mint OR transfer-in)
    ///         per address. `withdraw` requires `block.number >=
    ///         lastShareReceiveBlock[user] + LP_COOLDOWN_BLOCKS` — kills JIT
    ///         sandwich MEV around `borrow`/`repay`/`liquidate` donates.
    mapping(address => uint64) public lastShareReceiveBlock;

    /// @notice Frozen-in-time spot snapshot. `spotX18` = ETH per TOKEN at
    ///         block `blk`, captured pre-first-swap of that block. Together
    ///         with `prevSnap` forms the 2-level history used by
    ///         `_safeSpotX18`.
    struct PriceSnap {
        uint256 spotX18;
        uint64  blk;
    }

    /// @notice Pre-swap snapshot from the MOST RECENT active swap block.
    ///         Updated lazily in `beforeSwap` only on the first swap of a new
    ///         block. Inside the swap's own beforeSwap, `realETH/realToken`
    ///         still mirror end-of-previous-block state — that's what's
    ///         frozen here.
    PriceSnap public snap;

    /// @notice Pre-swap snapshot from the SECOND-MOST-RECENT active swap
    ///         block. `liquidate` and `borrow` READ this (not `snap`) so
    ///         that even a 2-block sustained pump-then-act cannot land —
    ///         the attacker's swap at block N will promote `snap` into
    ///         `prevSnap` only at block N+2 onward, and within blocks N..N+2
    ///         `prevSnap` still points to a pre-attack price.
    PriceSnap public prevSnap;

    // ─── Events ─────────────────────────────────────────────────────────────
    event PoolReady(PoolId indexed id, uint160 sqrtPriceX96, int24 currentTick);
    event Deposit(address indexed lp, uint256 ethIn, uint256 tokenIn, uint256 sharesOut);
    event Withdraw(address indexed lp, uint256 sharesIn, uint256 ethOut, uint256 tokenOut);
    event Borrowed(
        address indexed user,
        uint256 collateralIn,
        uint256 debtETH,
        uint256 netToUser,
        uint256 originationFee,
        uint256 rateBps,             // rate applied to this borrow (curve at borrow time)
        uint256 positionRateBps      // post-borrow blended rate on the position (== rateBps for fresh)
    );
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
    event DeployerTransferred(address indexed previous, address indexed next);

    // ─── Modifiers ──────────────────────────────────────────────────────────
    uint256 private _locked = 1;
    modifier nonReentrant() {
        if (_locked != 1) revert Reentrancy();
        _locked = 2;
        _;
        _locked = 1;
    }
    modifier onlyDeployer()    { if (msg.sender != deployer) revert NotDeployer(); _; }
    modifier onlyPoolManager() { if (msg.sender != address(poolManager)) revert NotPoolManager(); _; }

    // ─── Constructor ────────────────────────────────────────────────────────
    /// @param  token_  Underlying ERC20 that pairs against ETH.
    /// @dev    LP share token name/symbol are derived from `token_.symbol()`:
    ///           name   = "lo0pED <SYMBOL>/ETH LP"
    ///           symbol = "lo<SYMBOL>-ETH"
    ///         Token must implement IERC20Metadata.symbol().
    ///         PoolManager and FeeCollector are hardcoded — see constants above.
    ///         The initial `deployer` is `msg.sender` — typically the factory.
    constructor(IERC20 token_) ERC20(
        string.concat("lo0pED ", IERC20Metadata(address(token_)).symbol(), "/ETH LP"),
        string.concat("lo",      IERC20Metadata(address(token_)).symbol(), "-ETH")
    ) {
        if (address(token_) == address(0)) revert ZeroAddress();

        deployer = msg.sender;
        token    = token_;

        // Full-range, spacing-aligned. MIN/MAX_TICK are usable bounds.
        int24 minUsable = (TickMath.MIN_TICK / TICK_SPACING) * TICK_SPACING;
        int24 maxUsable = (TickMath.MAX_TICK / TICK_SPACING) * TICK_SPACING;
        tickLower = minUsable;
        tickUpper = maxUsable;

        Hooks.validateHookPermissions(IHooks(address(this)), getHookPermissions());
        emit DeployerTransferred(address(0), msg.sender);
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

    // ─── Deployer role ──────────────────────────────────────────────────────
    /// @notice The deployer's ONLY power. Hand the role to `next` (or pass
    ///         address(0) to burn it forever — once burned, no one can ever
    ///         call this function again, fully cementing the deployment).
    function setDeployer(address next) external onlyDeployer {
        emit DeployerTransferred(deployer, next);
        deployer = next;
    }

    // ─── Pool setup ─────────────────────────────────────────────────────────

    /// @notice Permissionless one-shot pool initialization at a chosen
    ///         sqrtPriceX96. Factory `deploy()` calls this atomically in the
    ///         same tx as construction so the picked price can't be front-run.
    ///         For direct (non-factory) deploys, broadcast deploy+init as a
    ///         private bundle if price-pick frontrun is a concern.
    ///         `beforeInitialize` enforces the canonical PoolKey, and
    ///         `PoolAlreadyInitialized` makes this a one-shot.
    function initializePool(uint160 sqrtPriceX96) external {
        if (poolInitialized) revert PoolAlreadyInitialized();
        // Reject sqrtPriceX96 beyond what `_sqrtPriceX96ToSpotX18` can
        // represent without truncating to zero. Past ~2^156 the two-step
        // shift-divide returns 0, which would brick `_safeSpotX18` until
        // the first swap promotes a real snap. Caps init to a sane band.
        if (sqrtPriceX96 < TickMath.MIN_SQRT_PRICE || sqrtPriceX96 > uint160(1) << 126) {
            revert SqrtPriceOutOfRange();
        }

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

        // Snapshot defaults — until the first swap fires `_captureSnapshot`,
        // both slots hold the init price. `lastSwapBlock = block.number` makes
        // the SAFE_LAG cooldown a no-op until real swap activity begins;
        // before any swap can possibly happen, deposits/borrows preserve the
        // pool ratio so the init spot remains the truth.
        lastSwapBlock = uint64(block.number);
        uint256 initSpotX18 = _sqrtPriceX96ToSpotX18(sqrtPriceX96);
        snap     = PriceSnap({spotX18: initSpotX18, blk: uint64(block.number)});
        prevSnap = PriceSnap({spotX18: initSpotX18, blk: uint64(block.number)});

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

        uint256 balBefore = token.balanceOf(address(this));
        token.safeTransferFrom(msg.sender, address(this), tokenIn);
        if (token.balanceOf(address(this)) - balBefore != tokenIn) {
            revert TokenTransferBalanceMismatch();
        }

        // Bootstrap path triggers on first-ever deposit (totalSupply == 0)
        // AND on re-bootstrap when the effective pool has drained to dust
        // (only dead-mint shares remain and reserves rounded down to 0).
        // Without the re-bootstrap, share math would divide by _effEth()/
        // _effTok() == 0 and the pool would be bricked. Old dead-mint shares
        // stay outstanding; the freshly-minted MINIMUM_SHARES accumulate to
        // 0xdead with no impact since they back a worthless residual claim.
        if (totalSupply() == 0 || _effEth() == 0 || _effTok() == 0) {
            // Bootstrap: depositor sets the new ratio. Mint sqrt(eth*token)
            // minus MINIMUM_SHARES (burned to address(0xdead) forever) to
            // defuse the share-inflation attack.
            uint256 totalMint = _sqrt(ethIn * tokenIn);
            if (totalMint <= MINIMUM_SHARES) revert MinSharesNotMet();
            sharesOut = totalMint - MINIMUM_SHARES;
            _mint(address(0xdead), MINIMUM_SHARES);
            // Re-anchor snapshot machinery to the new depositor's chosen
            // ratio. Reaches this branch on the very first deposit AND on
            // the next deposit after a full drain - in both cases the old
            // snap/prevSnap may point to a stale or wrong ratio.
            uint256 newSpotX18 = ethIn * 1e18 / tokenIn;
            snap     = PriceSnap({spotX18: newSpotX18, blk: uint64(block.number)});
            prevSnap = PriceSnap({spotX18: newSpotX18, blk: uint64(block.number)});
            lastSwapBlock = uint64(block.number);
        } else {
            // Ratio enforcement: ethIn / tokenIn must match the EFFECTIVE pool
            // ratio (realETH + totalDebt) / (realToken + totalLoanReserveToken).
            // Effective ratio keeps deposit pricing consistent across the
            // borrow lifecycle - JIT bot can't deposit at a "discounted" real
            // ratio between borrow and repay. Cross-multiply to avoid div.
            // Acceptable if |ethIn * effTok - tokenIn * effEth| < 1 permille.
            uint256 effE = _effEth();
            uint256 effT = _effTok();
            uint256 lhs = ethIn * effT;
            uint256 rhs = tokenIn * effE;
            uint256 maxSide = lhs > rhs ? lhs : rhs;
            uint256 diff = lhs > rhs ? lhs - rhs : rhs - lhs;
            if (diff * 1_000 > maxSide) revert RatioMismatch();

            // Pro-rata share mint against EFFECTIVE pool (not real). New
            // share % matches the fair fraction of total claimable value.
            sharesOut = ethIn * totalSupply() / effE;
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
        // JIT-LP cooldown: shares must have been held for >= LP_COOLDOWN_BLOCKS
        // to defend against sandwich-around-donate MEV (V1/V3/V4 in audit).
        // `lastShareReceiveBlock` resets on every mint or transfer-in via the
        // `_update` override, so the bot can't escape via fresh address.
        if (block.number < uint256(lastShareReceiveBlock[msg.sender]) + LP_COOLDOWN_BLOCKS) {
            revert LPCooldownActive();
        }

        uint256 supplyBefore = totalSupply();
        // Pro-rata target against the EFFECTIVE pool (realETH + outstanding
        // debt). User's effective claim is `sharesIn / supplyBefore` of that.
        // V4 only holds realETH/realToken, so if the user's effective claim
        // exceeds available liquidity (high utilization, lots of outstanding
        // debt), the withdraw reverts. User must wait for borrowers to repay.
        // Aave-style behavior. Closes JIT-LP: the deposit was priced into the
        // SAME effective pool, so withdrawing returns exactly the deposited
        // value (no refill bonus, no haircut).
        uint256 ethTarget = sharesIn * _effEth() / supplyBefore;
        uint256 tokTarget = sharesIn * _effTok() / supplyBefore;
        if (ethTarget > realETH || tokTarget > realToken) revert InsufficientLiquidity();

        _burn(msg.sender, sharesIn);

        // Size the V4 liquidity burn to deliver the target real amounts
        // exactly, rather than pro-rata of mirror liquidity (which would
        // over-burn against effective math).
        uint128 lqToBurn = _liquidityForAmounts(ethTarget, tokTarget);
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
        // Slippage on the actual paid amounts (post-fee). See note above.
        if (ethOut < minEthOut || tokenOut < minTokenOut) revert SlippageExceeded();

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
    /// @param collateralIn  TOKEN amount to lock as collateral.
    /// @param minDebtETH    Slippage floor on the resulting debt (and hence
    ///                      net ETH sent to msg.sender). Set to a low bound
    ///                      so a snapshot-vs-live spot drift between quote
    ///                      and execution can't shrink your payout silently.
    /// @param maxDebtETH    Slippage ceiling on the resulting debt — protects
    ///                      from over-borrowing if the snapshot is stale-high.
    function borrow(uint256 collateralIn, uint256 minDebtETH, uint256 maxDebtETH)
        external
        nonReentrant
        returns (uint256 debtETH, uint256 netToUser)
    {
        if (!poolInitialized) revert PoolNotInitializedErr();
        if (collateralIn == 0) revert CollateralBelowMin();
        if (realETH == 0 || realToken == 0) revert InsufficientLiquidity();

        uint256 balBefore = token.balanceOf(address(this));
        token.safeTransferFrom(msg.sender, address(this), collateralIn);
        if (token.balanceOf(address(this)) - balBefore != collateralIn) {
            revert TokenTransferBalanceMismatch();
        }

        // Value the collateral at the manipulation-resistant spot. Replaces
        // the old `lastSwapBlock` same-block guard — snapshot is strictly
        // stronger (also closes 1-2 block cross-block pump-then-borrow).
        uint256 spotX18 = _safeSpotX18();
        uint256 collateralValueETH = collateralIn * spotX18 / 1e18;
        debtETH = collateralValueETH * LTV_BPS / 10_000;
        if (debtETH < MIN_DEBT) revert DebtBelowMin();
        if (debtETH < minDebtETH || debtETH > maxDebtETH) revert DebtSlippage();
        if (debtETH >= realETH) revert InsufficientLiquidity();

        // System utilization cap: bounds pump-and-borrow attack profit to
        // UTILIZATION_CAP_BPS fraction of realETH. Stale safeSpot still
        // mis-values collateral on the upside, but extractable debt is
        // hard-limited regardless of attacker capital.
        if ((totalDebt + debtETH) * 10_000 > realETH * UTILIZATION_CAP_BPS) {
            revert UtilizationCapExceeded();
        }

        // Per-position cap applies to the position's TOTAL debt after this
        // borrow (incremental borrows accumulate). Defense-in-depth — at
        // launch defaults system cap binds first, but a future redeploy
        // could tune this lower.
        uint256 newPosDebt = positions[msg.sender].debt + debtETH;
        if (newPosDebt * 10_000 > realETH * MAX_BORROW_BPS) {
            revert MaxBorrowExceeded();
        }

        // Proportional withdraw — keeps spot constant. Uses the LIVE pool
        // ratio (not the snapshot) so the LP-side accounting matches the
        // V4 position exactly; snapshot governs valuation only.
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
        // Lock interest rate at borrow time. For incremental borrows, fold
        // the prior position's principal + accrued interest into the new
        // principal (re-anchor accrual clock to NOW) and compute a weighted
        // average of the old and new rates. totalDebt tracks total principal,
        // so it grows by (debtETH + capitalized interest) on incremental.
        uint256 newRate = currentBorrowRateBps();
        uint256 prevPrincipal = p.debt;
        if (prevPrincipal == 0) {
            p.rateBps = uint64(newRate);
            p.debt    = debtETH;
        } else {
            uint256 carriedDebt = getDebt(msg.sender);   // includes accrued interest
            uint256 totalAfter  = carriedDebt + debtETH;
            uint256 weighted    = (carriedDebt * uint256(p.rateBps) + debtETH * newRate) / totalAfter;
            p.rateBps = uint64(weighted);
            p.debt    = totalAfter;                      // principal carries accrued interest forward
        }
        p.collateral       += collateralIn;
        p.loanReserveToken += actualToken;
        p.openedAtBlock     = uint64(block.number);

        totalDebt              += (p.debt - prevPrincipal);    // = debtETH for fresh, debtETH + capitalized for incremental
        totalCollateralLocked  += collateralIn;
        totalLoanReserveToken  += actualToken;

        // protocolCut → FeeCollector (LOOP holders revenue).
        // netToUser → borrower's wallet.
        (bool sf,) = feeCollector.call{value: protocolCut}("");
        if (!sf) revert EthTransferFailed();
        (bool su,) = msg.sender.call{value: netToUser}("");
        if (!su) revert EthTransferFailed();

        emit Borrowed(msg.sender, collateralIn, debtETH, netToUser, origFee, newRate, uint256(p.rateBps));
    }

    // ─── Repay ──────────────────────────────────────────────────────────────

    /// @notice Repay debt — either full close or partial.
    ///         · Full close: msg.value >= currentDebt. Any overpayment is
    ///                       refunded; position is deleted; collateral fully
    ///                       returned.
    ///         · Partial:    msg.value must leave at least MIN_DEBT remaining
    ///                       effective debt. Caller can keep paying down via
    ///                       repeat calls.
    ///         No close fee — origination fee at borrow time covers the
    ///         protocol's per-position revenue floor.
    function repay() external payable nonReentrant {
        Position storage p = positions[msg.sender];
        if (p.debt == 0) revert NoOpenPosition();
        if (block.number < p.openedAtBlock + REPAY_COOLDOWN_BLOCKS) revert CooldownActive();

        uint256 sent = msg.value;
        if (sent == 0) revert RepayAmountMismatch();

        // Effective debt = principal + accrued interest. All repay math uses
        // this; principal-only `p.debt` is just the snapshot from last anchor.
        uint256 currentDebt = getDebt(msg.sender);
        uint256 prevPrincipal = p.debt;

        uint256 amount;       // effective debt being paid down (incl. interest portion)
        uint256 refund = 0;
        bool full;

        if (sent >= currentDebt) {
            // Full close: any overpayment refunded. Block timing means
            // `currentDebt` may grow 1+ wei between off-chain quote and
            // on-chain execution, so we allow >=.
            amount = currentDebt;
            refund = sent - currentDebt;
            full   = true;
        } else if ((currentDebt - sent) >= MIN_DEBT) {
            // Partial: leaves at least MIN_DEBT effective debt remaining
            amount = sent;
            full   = false;
        } else {
            revert InvalidRepayAmount();
        }

        uint256 collateralReturn = full ? p.collateral : p.collateral * amount / currentDebt;
        uint256 tokenRefill      = full ? p.loanReserveToken : p.loanReserveToken * amount / currentDebt;

        // Under-shoot liquidity by 1 unit so V4's `roundUp = true` math (which
        // can demand 1 extra wei on the settle side) never asks for more than
        // we have. Without this, `_handleRepay`'s legacy cap would silently
        // under-settle and V4 reverts the whole unlock with `CurrencyNotSettled`.
        uint128 lqAdded = _liquidityForAmounts(amount, tokenRefill);
        if (lqAdded < 2) revert ZeroAmount();
        unchecked { lqAdded -= 1; }

        bytes memory ret = poolManager.unlock(abi.encode(
            Action.REPAY,
            abi.encode(lqAdded, amount, tokenRefill)
        ));
        (uint256 actualETH, uint256 actualToken) = abi.decode(ret, (uint256, uint256));

        liquidity += lqAdded;
        realETH   += actualETH;
        realToken += actualToken;

        if (full) {
            delete positions[msg.sender];
            totalDebt -= prevPrincipal;
        } else {
            // Re-anchor: remaining effective debt becomes the new principal
            // and the accrual clock resets to NOW. Rate stays locked.
            uint256 newPrincipal = currentDebt - amount;
            p.debt = newPrincipal;
            p.collateral        -= collateralReturn;
            p.loanReserveToken  -= tokenRefill;
            p.openedAtBlock      = uint64(block.number);
            if (newPrincipal >= prevPrincipal) {
                totalDebt += (newPrincipal - prevPrincipal);
            } else {
                totalDebt -= (prevPrincipal - newPrincipal);
            }
        }
        totalCollateralLocked  -= collateralReturn;
        totalLoanReserveToken  -= tokenRefill;

        token.safeTransfer(msg.sender, collateralReturn);

        // Route any V4-rounding dust (amount > actualETH from under-shoot)
        // to FeeCollector — symmetric with `liquidate()`. Without this,
        // single-wei leftovers accumulate forever in the hook with no sweep.
        uint256 ethDust = amount - actualETH;
        if (ethDust > 0) {
            (bool sd,) = feeCollector.call{value: ethDust}("");
            if (!sd) revert EthTransferFailed();
        }
        uint256 tokDust = tokenRefill - actualToken;
        if (tokDust > 0) {
            token.safeTransfer(feeCollector, tokDust);
        }

        if (refund > 0) {
            (bool sr,) = msg.sender.call{value: refund}("");
            if (!sr) revert EthTransferFailed();
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
        // No per-block cap on liquidations — safeSpot's SAFE_LAG window
        // covers the manipulation surface, and proportional refill keeps
        // the pool ratio stable across consecutive liqs in the same block.
        // `lastLiquidationBlock` is still written below so `BlockedByLiquidation`
        // gates swaps/borrows/withdraws in this block (cross-pool buyback leg).

        Position storage p = positions[victim];
        if (p.debt == 0) revert NoOpenPosition();

        // Manipulation-resistant spot read. Inside the SAFE_LAG cooldown
        // window this returns `prevSnap` (pre-attack); outside the window
        // it returns the live pool ratio (settled, no manipulation in
        // flight). Used for BOTH the underwater check AND the bot payout
        // calc so a bot that pumps spot in this block gains nothing on
        // either side of the trade.
        uint256 spotX18 = _safeSpotX18();

        // Effective debt = principal + accrued interest. Liquidator must
        // pay this full amount; capped at collateral for bad-debt edges.
        uint256 prevPrincipal = p.debt;
        uint256 currentDebt = getDebt(victim);

        // Underwater check
        uint256 collateralValueETH = p.collateral * spotX18 / 1e18;
        if (collateralValueETH * 10_000 >= currentDebt * LIQUIDATION_THRESHOLD_BPS) revert NotUnderwater();

        uint256 debtAmount = currentDebt;
        if (msg.value < debtAmount) revert RepayAmountMismatch();

        // Bot receives `debt`-worth of TOKEN at 2.5 % discount.
        //   debt-equivalent TOKEN at spot   = debt × 1e18 / spotX18
        //   with 2.5 % bonus                = × (10_000 + 250) / 10_000
        // Cap at collateral for the bad-debt edge (HF < 1.026).
        uint256 tokenToBot =
            (debtAmount * (10_000 + LIQUIDATION_DISCOUNT_BPS) * 1e18)
            / (spotX18 * 10_000);
        if (tokenToBot > p.collateral) tokenToBot = p.collateral;

        uint256 residualToken = p.collateral - tokenToBot;
        uint256 collateral = p.collateral;
        uint256 loanReserve = p.loanReserveToken;

        // LP refill: full debt ETH + loanReserveToken + residual collateral.
        // V4 modifyLiquidity will use only the proportional amounts needed at
        // the current pool ratio; any side excess is routed to FC below.
        uint256 refillETH   = debtAmount;
        uint256 refillToken = loanReserve + residualToken;

        // CEI: clear ALL position state BEFORE the external `unlock` call so
        // any reentry via a malicious token (during `_handleLiquidate`'s
        // settle-to-PM) sees a fully closed position. Without this, read-
        // only reentry from inside the unlock callback could observe
        // `isUnderwater(victim) == true` despite the liq being in flight.
        delete positions[victim];
        totalDebt              -= prevPrincipal;    // totalDebt tracks principal; accrued portion becomes LP profit
        totalCollateralLocked  -= collateral;
        totalLoanReserveToken  -= loanReserve;
        lastLiquidationBlock   = uint64(block.number);

        // Under-shoot liquidity by 1 unit so V4's `roundUp = true` math never
        // asks for more ETH/TOKEN than we have. Same rationale as in `repay()`.
        uint128 lqAdded = _liquidityForAmounts(refillETH, refillToken);
        if (lqAdded < 2) revert ZeroAmount();
        unchecked { lqAdded -= 1; }

        bytes memory ret = poolManager.unlock(abi.encode(
            Action.LIQUIDATE,
            abi.encode(lqAdded, refillETH, refillToken)
        ));
        (uint256 actualETH, uint256 actualToken) = abi.decode(ret, (uint256, uint256));

        liquidity += lqAdded;
        realETH   += actualETH;
        realToken += actualToken;

        // Side that didn't fully fit the current ratio → FeeCollector.
        if (actualETH < refillETH) {
            uint256 excessETH = refillETH - actualETH;
            (bool se,) = feeCollector.call{value: excessETH}("");
            if (!se) revert EthTransferFailed();
        }
        if (actualToken < refillToken) {
            uint256 excessToken = refillToken - actualToken;
            token.safeTransfer(feeCollector, excessToken);
        }

        // Pay bot in TOKEN (state already final from the CEI block above)
        token.safeTransfer(msg.sender, tokenToBot);

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
        if (sender != address(this)) revert NotDeployer();
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

        // SANDWICH DEFENSE: capture the pre-swap pool ratio into the snapshot
        // history (no-op if this isn't the first external swap of the block).
        // Runs before any state-changing path in beforeSwap so the snapshot
        // is always pre-this-block.
        _captureSnapshot();

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

        // Sync realETH/realToken from V4's current state.
        if (sender != address(this) && liquidity > 0) {
            (uint160 sqrtP_,,,) = poolManager.getSlot0(_poolId());
            (realETH, realToken) = LiquidityAmounts.getAmountsForLiquidity(
                sqrtP_,
                TickMath.getSqrtPriceAtTick(tickLower),
                TickMath.getSqrtPriceAtTick(tickUpper),
                liquidity
            );
        }

        if (sender == address(this)) return (IHooks.afterSwap.selector, 0);

        // Skim layout:
        //   · BUY  exact-input  (zeroForOne && amountSpecified<0) → handled in beforeSwap
        //   · BUY  exact-output (zeroForOne && amountSpecified>0) → skim ETH from input  (unspecified)
        //   · SELL exact-input  (!zeroForOne && amountSpecified<0)→ skim ETH from output (unspecified)
        //   · SELL exact-output (!zeroForOne && amountSpecified>0)→ skim TOKEN from input (unspecified)
        // The afterSwap int128 return goes to the UNSPECIFIED currency delta.
        bool exactInputBuy = params.zeroForOne && params.amountSpecified < 0;
        if (exactInputBuy) return (IHooks.afterSwap.selector, 0);

        // Determine which currency carries the unspecified leg.
        // For SELLs unspecified = currency0 (ETH). For BUYs unspecified = currency1 (TOKEN),
        // BUT we're skimming on the INPUT for BUY exact-output, which is currency0 (ETH).
        // Wait — for BUY (zeroForOne) the unspecified for exact-output IS currency0 (input ETH).
        // V4 convention: unspecified = the currency whose amount is computed (not given).
        //   exact-input zeroForOne:  specified=in (c0), unspecified=out (c1)
        //   exact-output zeroForOne: specified=out (c1), unspecified=in (c0)
        //   exact-input !zeroForOne: specified=in (c1), unspecified=out (c0)
        //   exact-output !zeroForOne:specified=out (c0), unspecified=in (c1)
        Currency feeCurrency;
        uint256 ethOrTokenAmount;
        if (params.zeroForOne) {
            // exact-output BUY (already filtered exact-input BUY above): unspecified = c0 (ETH input)
            int128 a0 = delta.amount0();
            if (a0 >= 0) return (IHooks.afterSwap.selector, 0); // user didn't pay ETH? skip
            ethOrTokenAmount = uint256(uint128(-a0));
            feeCurrency = key.currency0;
        } else {
            if (params.amountSpecified < 0) {
                // SELL exact-input: unspecified = c0 (ETH output)
                int128 a0 = delta.amount0();
                if (a0 <= 0) return (IHooks.afterSwap.selector, 0);
                ethOrTokenAmount = uint256(uint128(a0));
                feeCurrency = key.currency0;
            } else {
                // SELL exact-output: unspecified = c1 (TOKEN input)
                int128 a1 = delta.amount1();
                if (a1 >= 0) return (IHooks.afterSwap.selector, 0);
                ethOrTokenAmount = uint256(uint128(-a1));
                feeCurrency = key.currency1;
            }
        }

        uint256 fee = ethOrTokenAmount * PROTOCOL_SWAP_FEE_BPS / 10_000;
        if (fee == 0) return (IHooks.afterSwap.selector, 0);

        poolManager.take(feeCurrency, feeCollector, fee);
        emit Swapped(tx.origin, params.zeroForOne, ethOrTokenAmount, fee);
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

        // Under-shoot liquidity by 1 unit so V4's `roundUp = true` math (which
        // can demand 1 extra wei on the settle side) never asks for more than
        // we have. Without this, the first deposit (no hook ETH dust to cover)
        // would revert `CurrencyNotSettled` on a rounding boundary.
        uint128 lqAdded = _liquidityForAmounts(ethIn, tokenIn);
        // Reject amounts so tiny that the under-shoot would zero them out —
        // otherwise we mint shares + bump mirrors but add 0 V4 liquidity
        // (silent zero-liquidity deposit, bricks subsequent ops).
        if (lqAdded < 2) revert ZeroAmount();
        unchecked { lqAdded -= 1; }

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

        // V4 returns mixed-sign deltas on add: negative = principal we owe,
        // positive = LP swap fees auto-harvested by V4. Settle the negative
        // side; re-donate the positive side so swap-fee yield stays with LPs.
        int128 a0 = delta.amount0();
        int128 a1 = delta.amount1();

        if (a0 < 0) {
            uint256 ethOwed = uint256(uint128(-a0));
            poolManager.sync(CurrencyLibrary.ADDRESS_ZERO);
            poolManager.settle{value: ethOwed}();
        }
        if (a1 < 0) {
            uint256 tokenOwed = uint256(uint128(-a1));
            poolManager.sync(poolKey.currency1);
            token.safeTransfer(address(poolManager), tokenOwed);
            poolManager.settle();
        }
        // Re-donate positive deltas in one call — V4's donate creates a
        // matching negative delta on the donor that cancels the positive
        // we received from modifyLiquidity, no extra settle needed.
        uint256 ethRecv = a0 > 0 ? uint256(uint128(a0)) : 0;
        uint256 tokenRecv = a1 > 0 ? uint256(uint128(a1)) : 0;
        if (ethRecv > 0 || tokenRecv > 0) {
            poolManager.donate(poolKey, ethRecv, tokenRecv, "");
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

        // V4 returns principal + accrued LP fees. Take only the borrow target;
        // re-donate the rest (= LP swap fees) back to the position so the
        // 0.5% LP fee tier actually accrues to LPs (NOT to FeeCollector).
        uint256 grossETH   = uint256(uint128(a0));
        uint256 grossToken = uint256(uint128(a1));
        uint256 actualETH   = grossETH   > ethTarget   ? ethTarget   : grossETH;
        uint256 actualToken = grossToken > tokenTarget ? tokenTarget : grossToken;
        uint256 excessETH   = grossETH   - actualETH;
        uint256 excessToken = grossToken - actualToken;

        poolManager.take(CurrencyLibrary.ADDRESS_ZERO, address(this), actualETH);
        poolManager.take(poolKey.currency1, address(this), actualToken);
        if (excessETH > 0 || excessToken > 0) {
            poolManager.donate(poolKey, excessETH, excessToken, "");
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
            token.safeTransfer(address(poolManager), tokenOwed);
            poolManager.settle();
        }
        // Accrued V4 LP swap fees come back as positive deltas. Re-donate
        // them to the position — V4's `donate` creates a matching negative
        // delta that cancels the positive we got from modifyLiquidity, so
        // the call alone fully settles. Without this, every repay/liquidate
        // would siphon LP fees to FeeCollector, breaking the LP economics.
        if (ethRecv > 0 || tokenRecv > 0) {
            poolManager.donate(poolKey, ethRecv, tokenRecv, "");
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

    /// @notice Effective pool ETH for LP-share math: realETH + outstanding debt
    ///         (which is "out" but will return on repay/liquidate). Treating
    ///         loaned-out value as still-LP-owned closes the JIT-LP exploit
    ///         where a bot deposits between borrow and repay to capture the
    ///         refill bonus. The refill is restoration, not new yield —
    ///         effective pool stays constant across borrow/repay cycles.
    ///         Real LP yield (swap fees, orig fees, interest, liq residual)
    ///         still flows into realETH and is captured by all shareholders.
    function _effEth() internal view returns (uint256) {
        return realETH + totalDebt;
    }

    /// @notice Effective pool TOKEN counterpart. realToken + loanReserveToken
    ///         (tokens held aside per borrower, returned on repay/liq).
    function _effTok() internal view returns (uint256) {
        return realToken + totalLoanReserveToken;
    }

    /// @notice Current borrow rate (bps APR) given pool utilization. New
    ///         borrows lock IN this rate. Existing positions are unaffected.
    ///         Capped at MAX_RATE_BPS so `getDebt`'s interest multiplier can
    ///         never blow up even if a future redeploy loosens the util cap.
    function currentBorrowRateBps() public view returns (uint256 rateBps) {
        if (realETH == 0) return BASE_RATE_BPS;
        uint256 util = totalDebt * 10_000 / realETH;
        if (util <= OPTIMAL_UTIL_BPS) {
            rateBps = BASE_RATE_BPS + util * SLOPE_NORMAL_BPS / 10_000;
        } else {
            rateBps = BASE_RATE_BPS + OPTIMAL_UTIL_BPS * SLOPE_NORMAL_BPS / 10_000;
            rateBps += (util - OPTIMAL_UTIL_BPS) * SLOPE_JUMP_BPS / 10_000;
        }
        if (rateBps > MAX_RATE_BPS) rateBps = MAX_RATE_BPS;
    }

    /// @notice Effective debt owed by `user` including accrued interest since
    ///         the position was last anchored. Linear approximation — over a
    ///         year at 10 % APR the linear-vs-compound error is ~0.5 %, in the
    ///         borrower's favor (slight underaccrual).
    function getDebt(address user) public view returns (uint256) {
        Position memory p = positions[user];
        if (p.debt == 0) return 0;
        if (block.number <= uint256(p.openedAtBlock)) return p.debt;
        uint256 secsElapsed = (block.number - uint256(p.openedAtBlock)) * SECS_PER_BLOCK;
        uint256 interest = p.debt * uint256(p.rateBps) * secsElapsed / (10_000 * SECS_PER_YEAR);
        return p.debt + interest;
    }

    function isUnderwater(address user) external view returns (bool) {
        Position memory p = positions[user];
        if (p.debt == 0) return false;
        uint256 currentDebt = getDebt(user);
        // Match `liquidate()`'s exact spot read so the UI/bots' "is this
        // liquidatable right now?" answer agrees with what would happen on-
        // chain. Inside SAFE_LAG cooldown that's `prevSnap`; outside, live.
        uint256 spotX18;
        if (block.number > uint256(lastSwapBlock) + SAFE_LAG) {
            if (realToken == 0) return false;
            spotX18 = realETH * 1e18 / realToken;
        } else {
            spotX18 = prevSnap.spotX18;
            if (spotX18 == 0) return false;
        }
        uint256 collValue = p.collateral * spotX18 / 1e18;
        return collValue * 10_000 < currentDebt * LIQUIDATION_THRESHOLD_BPS;
    }

    /// @notice Quote a deposit: how many shares would `ethIn` mint?
    ///         Uses EFFECTIVE pool values (realETH + totalDebt) for consistent
    ///         pricing across the borrow lifecycle.
    function quoteDeposit(uint256 ethIn) external view returns (uint256 sharesOut, uint256 tokenRequired) {
        if (totalSupply() == 0) return (0, 0);  // first depositor - open-ended
        uint256 effE = _effEth();
        if (effE == 0) return (0, 0);
        tokenRequired = ethIn * _effTok() / effE;
        sharesOut     = ethIn * totalSupply() / effE;
    }

    /// @notice Quote a borrow: how much ETH would `collateralIn` get, and at
    ///         what rate? `rateBps` is the rate that would be LOCKED in for a
    ///         fresh position (i.e. live curve value, capped at MAX_RATE_BPS).
    ///         Per-position cap is checked against a fresh position — use
    ///         `quoteBorrowFor(user, collateralIn)` for incremental accuracy.
    function quoteBorrow(uint256 collateralIn)
        external
        view
        returns (uint256 debtETH, uint256 netToUser, uint256 rateBps, bool feasible)
    {
        rateBps = currentBorrowRateBps();
        if (realETH == 0 || realToken == 0) return (0, 0, rateBps, false);
        uint256 spotX18;
        if (block.number > uint256(lastSwapBlock) + SAFE_LAG) {
            spotX18 = realETH * 1e18 / realToken;
        } else {
            spotX18 = prevSnap.spotX18;
            if (spotX18 == 0) return (0, 0, rateBps, false);
        }
        uint256 collateralValueETH = collateralIn * spotX18 / 1e18;
        debtETH = collateralValueETH * LTV_BPS / 10_000;
        if (debtETH < MIN_DEBT) return (debtETH, 0, rateBps, false);
        if (debtETH >= realETH) return (debtETH, 0, rateBps, false);
        if ((totalDebt + debtETH) * 10_000 > realETH * UTILIZATION_CAP_BPS) {
            return (debtETH, 0, rateBps, false);
        }
        if (debtETH * 10_000 > realETH * MAX_BORROW_BPS) {
            return (debtETH, 0, rateBps, false);
        }
        uint256 origFee = debtETH * ORIG_FEE_BPS / LTV_BPS;
        netToUser = debtETH - origFee;
        feasible = true;
    }

    /// @notice Per-user borrow quote — accurate for incremental borrows.
    ///         Returns the rate that the borrow would lock at (`newRateBps`)
    ///         AND the position's blended rate AFTER this borrow lands
    ///         (`positionRateBps`). For fresh positions the two are equal;
    ///         for incremental, `positionRateBps` is the principal-weighted
    ///         average that will actually drive future interest accrual.
    function quoteBorrowFor(address user, uint256 collateralIn)
        external
        view
        returns (
            uint256 debtETH,
            uint256 netToUser,
            uint256 newRateBps,
            uint256 positionRateBps,
            bool    feasible
        )
    {
        newRateBps = currentBorrowRateBps();
        if (realETH == 0 || realToken == 0) {
            positionRateBps = newRateBps;
            return (0, 0, newRateBps, newRateBps, false);
        }
        uint256 spotX18;
        if (block.number > uint256(lastSwapBlock) + SAFE_LAG) {
            spotX18 = realETH * 1e18 / realToken;
        } else {
            spotX18 = prevSnap.spotX18;
            if (spotX18 == 0) {
                positionRateBps = newRateBps;
                return (0, 0, newRateBps, newRateBps, false);
            }
        }
        uint256 collateralValueETH = collateralIn * spotX18 / 1e18;
        debtETH = collateralValueETH * LTV_BPS / 10_000;

        // Compute blended rate preview (matches borrow() math)
        Position memory p = positions[user];
        if (p.debt == 0) {
            positionRateBps = newRateBps;
        } else {
            uint256 carried = getDebt(user);
            uint256 totalAfter = carried + debtETH;
            if (totalAfter == 0) {
                positionRateBps = newRateBps;
            } else {
                positionRateBps =
                    (carried * uint256(p.rateBps) + debtETH * newRateBps) / totalAfter;
            }
        }

        if (debtETH < MIN_DEBT) return (debtETH, 0, newRateBps, positionRateBps, false);
        if (debtETH >= realETH) return (debtETH, 0, newRateBps, positionRateBps, false);
        if ((totalDebt + debtETH) * 10_000 > realETH * UTILIZATION_CAP_BPS) {
            return (debtETH, 0, newRateBps, positionRateBps, false);
        }
        uint256 newPosDebt = p.debt + debtETH;
        if (newPosDebt * 10_000 > realETH * MAX_BORROW_BPS) {
            return (debtETH, 0, newRateBps, positionRateBps, false);
        }
        uint256 origFee = debtETH * ORIG_FEE_BPS / LTV_BPS;
        netToUser = debtETH - origFee;
        feasible = true;
    }

    // ─── Aggregated views (one RPC = full UI state) ─────────────────────────

    /// @notice Snapshot of every dynamic field the UI needs in one call. Pass
    ///         `user = address(0)` to read pool state only without the user
    ///         block (saves a few token external-call gas).
    // getMarketState() and getConstants() were both removed: combined they
    // pushed the runtime past EIP-170 24 KB. They live in the separate
    // `LendingHookV4Lens` contract, which reads the hook's public state and
    // aggregates the same views. The lens is permissionless and stateless,
    // so off-chain callers just point at the deployed lens instead.

    // getConstants() removed: every field is already a public constant
    // (LTV_BPS, ORIG_FEE_BPS, ...) callable individually. The struct return
    // cost ~700 bytes of runtime code at no real UX win since frontends
    // either bake the values in or batch the reads via multicall.

    /// @notice Withdraw quote: burning `sharesIn` would return what ETH/TOKEN?
    ///         Uses EFFECTIVE pool (real + outstanding loans). If the resulting
    ///         target exceeds available realETH/realToken, withdraw would
    ///         revert with InsufficientLiquidity - UI should warn the user
    ///         to wait for borrowers to repay before exiting.
    function quoteWithdraw(uint256 sharesIn) external view returns (uint256 ethOut, uint256 tokenOut) {
        uint256 supply = totalSupply();
        if (supply == 0 || sharesIn == 0) return (0, 0);
        ethOut   = sharesIn * _effEth() / supply;
        tokenOut = sharesIn * _effTok() / supply;
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

    /// @dev Track LP-share receipts. Resets the cooldown on any inbound
    ///      transfer (or mint) so that a JIT attacker can't bypass the
    ///      `withdraw` cooldown by routing shares through a fresh address.
    ///      Burns (`to == address(0)`) are no-ops.
    function _update(address from, address to, uint256 value) internal override {
        super._update(from, to, value);
        if (to != address(0)) {
            lastShareReceiveBlock[to] = uint64(block.number);
        }
    }

    function _sqrt(uint256 x) internal pure returns (uint256 y) {
        if (x == 0) return 0;
        uint256 z = (x + 1) / 2;
        y = x;
        while (z < y) { y = z; z = (x / z + z) / 2; }
    }

    // ─── Sandwich-defense helpers ───────────────────────────────────────────

    /// @notice Promote `snap` to `prevSnap` and capture the live pre-swap
    ///         pool ratio into `snap` — but only once per block (the first
    ///         swap of a new block triggers; subsequent swaps in the same
    ///         block leave both slots untouched). Called at the top of
    ///         `beforeSwap` for every external swap.
    function _captureSnapshot() internal {
        if (block.number > snap.blk && realToken > 0) {
            prevSnap = snap;
            snap = PriceSnap({
                spotX18: realETH * 1e18 / realToken,
                blk:     uint64(block.number)
            });
        }
    }

    /// @notice Manipulation-resistant spot read used by `liquidate` and
    ///         `borrow`. Picks between two sources:
    ///           · current `realETH/realToken` when the pool has been swap-
    ///             quiet for `SAFE_LAG + 1` blocks (no active manipulation
    ///             possible);
    ///           · the older `prevSnap` snapshot when there's been recent
    ///             swap activity (the attacker's manipulation has not yet
    ///             reached `prevSnap`, so the read is pre-attack).
    function _safeSpotX18() internal view returns (uint256 spot) {
        if (block.number > uint256(lastSwapBlock) + SAFE_LAG) {
            if (realToken == 0) revert InsufficientLiquidity();
            return realETH * 1e18 / realToken;
        }
        spot = prevSnap.spotX18;
        if (spot == 0) revert InsufficientLiquidity();
    }

    /// @notice Convert V4's `sqrtPriceX96` (= sqrt(token1/token0) * 2^96)
    ///         into our internal `spotX18` format (= ETH per TOKEN scaled by
    ///         1e18). Pool layout fixed: currency0 = ETH, currency1 = TOKEN,
    ///         so `price = TOKEN/ETH` and `spotX18 = 1e18 / price`.
    ///         Computation: `1e18 * 2^192 / sqrtPriceX96^2`, split into two
    ///         shifts/divides so the intermediates stay inside uint256.
    function _sqrtPriceX96ToSpotX18(uint160 sqrtPriceX96) internal pure returns (uint256) {
        if (sqrtPriceX96 == 0) return 0;
        uint256 sq    = uint256(sqrtPriceX96);
        uint256 step1 = (uint256(1e18) << 96) / sq;       // ≈ 2^156 / sq, fits
        return (step1 << 96) / sq;                         // final mulDiv equiv
    }

    // Accept ETH refunds from PoolManager
    receive() external payable {}
}

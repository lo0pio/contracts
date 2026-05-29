// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/*//////////////////////////////////////////////////////////////
                              lo0p
                    web · https://lo0p.io
                    x   · https://x.com/lo0pio
                    tg  · https://t.me/lo0pio
//////////////////////////////////////////////////////////////*/

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {LendingHookV4} from "./LendingHookV4.sol";

/// @title  LendingHookV4Lens - off-chain read aggregator for V4 hooks
/// @notice Stateless. One deployment serves every hook. Folds 20-odd
///         individual getters into one struct so dapps/indexers can fetch
///         the full market + user snapshot in a single RPC.
///
///         Lives here so `LendingHookV4` itself stays under EIP-170. The
///         hook only ships the load-bearing logic; this lens carries the
///         struct-encoding bloat that frontends actually consume.
///
///         Pure view contract - no state, no admin, no migration risk.
///         Safe to redeploy/replace any time without touching the hook.
contract LendingHookV4Lens {
    struct MarketState {
        // Pool state
        uint256 realETH;
        uint256 realToken;
        uint256 effectiveETH;
        uint256 effectiveToken;
        uint128 liquidity;
        uint256 totalShares;
        uint256 totalDebt;
        uint256 totalCollateral;
        uint256 totalLoanReserveToken;
        uint256 spotX18;
        uint256 safeSpotX18;
        uint160 sqrtPriceX96;
        uint64  lastSwapBlock;
        uint64  lastLiquidationBlock;
        uint64  snapBlk;
        uint256 snapSpotX18;
        uint64  prevSnapBlk;
        uint256 prevSnapSpotX18;
        bool    poolInitialized;
        uint256 currentBorrowRateBps;
        // User state (zero when user == address(0))
        uint256 userEthBalance;
        uint256 userTokenBalance;
        uint256 userTokenAllowance;
        uint256 userShareBalance;
        uint256 userCollateral;
        uint256 userDebt;             // effective (principal + accrued)
        uint256 userPrincipal;
        uint256 userRateBps;
        uint256 userLoanReserveToken;
        uint64  userOpenedAtBlock;
        bool    userIsUnderwater;
    }

    struct ProtocolConstants {
        uint256 ltvBps;
        uint256 origFeeBps;
        uint24  lpSwapFeePips;
        uint256 protocolSwapFeeBps;
        uint256 liquidationThresholdBps;
        uint256 liquidationDiscountBps;
        uint256 repayCooldownBlocks;
        uint256 minDebt;
        uint256 minimumShares;
        uint256 utilizationCapBps;
        uint256 maxBorrowBps;
        uint256 baseRateBps;
        uint256 optimalUtilBps;
        uint256 slopeNormalBps;
        uint256 slopeJumpBps;
        uint256 maxRateBps;
        uint64  safeLag;
        uint64  lpCooldownBlocks;
    }

    function getMarketState(LendingHookV4 hook, address user)
        external
        view
        returns (MarketState memory s)
    {
        IERC20 tok = hook.token();
        s.realETH               = hook.realETH();
        s.realToken             = hook.realToken();
        s.totalDebt             = hook.totalDebt();
        s.totalCollateral       = hook.totalCollateralLocked();
        s.totalLoanReserveToken = hook.totalLoanReserveToken();
        s.effectiveETH          = s.realETH + s.totalDebt;
        s.effectiveToken        = s.realToken + s.totalLoanReserveToken;
        s.liquidity             = hook.liquidity();
        s.totalShares           = hook.totalSupply();
        s.lastSwapBlock         = hook.lastSwapBlock();
        s.lastLiquidationBlock  = hook.lastLiquidationBlock();
        s.currentBorrowRateBps  = hook.currentBorrowRateBps();
        if (s.realToken > 0) s.spotX18 = s.realETH * 1e18 / s.realToken;

        (s.snapSpotX18, s.snapBlk)         = hook.snap();
        (s.prevSnapSpotX18, s.prevSnapBlk) = hook.prevSnap();

        // Mirror `_safeSpotX18` without reverting - UI must render even
        // before any swap promotes a real snap.
        s.safeSpotX18 = block.number > uint256(s.lastSwapBlock) + hook.SAFE_LAG()
            ? s.spotX18
            : s.prevSnapSpotX18;

        s.poolInitialized = hook.poolInitialized();
        // sqrtPriceX96 intentionally left 0 here. Frontends that need the
        // raw V4 spot can compute one from spotX18 = realETH * 1e18 / realToken,
        // or read PoolManager.getSlot0 directly with the well-known pool id.

        if (user != address(0)) {
            s.userEthBalance     = user.balance;
            s.userTokenBalance   = tok.balanceOf(user);
            s.userTokenAllowance = tok.allowance(user, address(hook));
            s.userShareBalance   = hook.balanceOf(user);
            LendingHookV4.Position memory p = hook.getPosition(user);
            s.userCollateral       = p.collateral;
            s.userPrincipal        = p.debt;
            s.userRateBps          = uint256(p.rateBps);
            s.userLoanReserveToken = p.loanReserveToken;
            s.userOpenedAtBlock    = p.openedAtBlock;
            s.userDebt             = hook.getDebt(user);
            if (p.debt > 0 && s.safeSpotX18 > 0) {
                uint256 collValue = p.collateral * s.safeSpotX18 / 1e18;
                s.userIsUnderwater =
                    collValue * 10_000 < s.userDebt * hook.LIQUIDATION_THRESHOLD_BPS();
            }
        }
    }

    /// Every protocol constant in one call. Frontends cache this on mount.
    function getConstants(LendingHookV4 hook)
        external
        view
        returns (ProtocolConstants memory c)
    {
        c.ltvBps                  = hook.LTV_BPS();
        c.origFeeBps              = hook.ORIG_FEE_BPS();
        c.lpSwapFeePips           = hook.LP_SWAP_FEE_PIPS();
        c.protocolSwapFeeBps      = hook.PROTOCOL_SWAP_FEE_BPS();
        c.liquidationThresholdBps = hook.LIQUIDATION_THRESHOLD_BPS();
        c.liquidationDiscountBps  = hook.LIQUIDATION_DISCOUNT_BPS();
        c.repayCooldownBlocks     = hook.REPAY_COOLDOWN_BLOCKS();
        c.minDebt                 = hook.MIN_DEBT();
        c.minimumShares           = hook.MINIMUM_SHARES();
        c.utilizationCapBps       = hook.UTILIZATION_CAP_BPS();
        c.maxBorrowBps            = hook.MAX_BORROW_BPS();
        c.baseRateBps             = hook.BASE_RATE_BPS();
        c.optimalUtilBps          = hook.OPTIMAL_UTIL_BPS();
        c.slopeNormalBps          = hook.SLOPE_NORMAL_BPS();
        c.slopeJumpBps            = hook.SLOPE_JUMP_BPS();
        c.maxRateBps              = hook.MAX_RATE_BPS();
        c.safeLag                 = hook.SAFE_LAG();
        c.lpCooldownBlocks        = hook.LP_COOLDOWN_BLOCKS();
    }
}

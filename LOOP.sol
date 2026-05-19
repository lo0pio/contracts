// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/*//////////////////////////////////////////////////////////////
                              lo0p
                    web · https://lo0p.io
                    x   · https://x.com/lo0pio
                    tg  · https://t.me/lo0pio
//////////////////////////////////////////////////////////////*/

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @notice LOOP — fixed-supply ERC20 token of the lo0p protocol. 1M minted to the
///         lending hook in constructor. No team allocation, no mint after deploy.
///         burn() callable by anyone for own balance; the hook calls it for liquidations
///         on tokens it holds (collateral + loan reserve).
contract LOOP is ERC20 {
    uint256 public constant TOTAL_SUPPLY = 1_000_000 * 1e18;

    error ZeroAddress();

    constructor(address mintTo) ERC20("LO0P", "LO0P") {
        if (mintTo == address(0)) revert ZeroAddress();
        _mint(mintTo, TOTAL_SUPPLY);
    }

    /// @notice Burn from caller's balance.
    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }
}

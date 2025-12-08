# Sepolia Deployment Summary

## Contract Addresses

**Network:** Sepolia Testnet  
**Deployer:** `0x4b992F2Fbf714C0fCBb23baC5130Ace48CaD00cd`

### Contracts
- **PrivacyHook**: `0x72Acb50A8a6C7d39b08C56558fdeFfaF7C2b885A`
- **HybridFHERC20 Token0**: `0xd458768065296912E75C7962c7fF502FB85A5255`
- **HybridFHERC20 Token1**: `0x9c14e6351eB6a0526EDB6c798bE3a51fF26E1a59`

## Verified Interactions

### ✅ Working Functions

**View Functions:**
- `relayer()` - Returns: `0x4b992F2Fbf714C0fCBb23baC5130Ace48CaD00cd`
- `poolManager()` - Returns: `0x61B3f2011A92d183C7dbaDBdA940a7555Ccf9227`
- `token0()` - Returns: `0xd458768065296912E75C7962c7fF502FB85A5255`
- `token1()` - Returns: `0x9c14e6351eB6a0526EDB6c798bE3a51fF26E1a59`
- `isIntentActive(address)` - Returns: `false`
- `getHookPermissions()` - Returns: `(false, false, true, false, false, true, true, true, false, false, false, false, false)`
  - Enabled: `beforeAddLiquidity`, `afterRemoveLiquidity`, `beforeSwap`, `afterSwap`

**Public Token Operations:**
- `mint(address, uint256)` - ✅ Successfully minted 100 tokens
- `approve(address, uint256)` - ✅ Successfully approved hook
- `balanceOf(address)` - ✅ Returns public balance

**Hook Functions:**
- `cancelIntent()` - ✅ Successfully executed (Tx: `0x23351e8c8a6bf0ae30fdbf44be69add1c2de3e9c2c891d8cb52c8f0dae6e2b66`)
- `depositToken0(uint128)` - ✅ **Unexpectedly succeeded!** (Tx: `0x721c30e2fd035b4fd93148ea126fa3a5467c2533174191c987a61d78e9d5427f`)
  - Note: Stores encrypted hash but FHE operations won't work for actual use

### ⚠️ FHE Functions (Structure Present, Operations Limited)

**Encrypted State (Returns Hashes):**
- `encBalances(address)` - Returns encrypted hash (not decryptable without FHE)
- `totalEncryptedSupply()` - Returns encrypted hash
- `intents(address)` - Returns struct with encrypted values
- `residuals(address)` - Returns struct with encrypted values

**FHE Operations (Cannot Execute on Sepolia):**
- `submitIntent(InEuint128, InEbool)` - Requires FHE encryption
- `settleMatched(address, address, InEuint128)` - Requires FHE encryption + relayer
- `requestWithdrawToken0/1(InEuint128)` - Requires FHE encryption
- `finalizeWithdrawToken0/1(euint128)` - Requires FHE decryption

## Transaction History

1. **Token Minting:**
   - Token0: 100 tokens minted
   - Token1: 100 tokens minted

2. **Approvals:**
   - Token0 approved for hook
   - Token1 approved for hook

3. **Deposit:**
   - 10 Token0 deposited (Tx: `0x721c30e2fd035b4fd93148ea126fa3a5467c2533174191c987a61d78e9d5427f`)
   - Encrypted balance hash stored: `0x850ebff015260cbbd738bcda5ed13f1513f5ac4d437c9a10ebc0fa7184cb8600`

4. **Intent Cancellation:**
   - Intent cancelled (Tx: `0x23351e8c8a6bf0ae30fdbf44be69add1c2de3e9c2c891d8cb52c8f0dae6e2b66`)

## Hook Permissions Status

```
beforeInitialize:        false
afterInitialize:         false
beforeAddLiquidity:      true  ✅
afterAddLiquidity:       false
beforeRemoveLiquidity:   false
afterRemoveLiquidity:    true  ✅
beforeSwap:              true  ✅
afterSwap:               true  ✅
beforeDonate:            false
afterDonate:             false
beforeSwapReturnDelta:   false
afterSwapReturnDelta:    false
afterAddLiquidityReturnDelta: false
afterRemoveLiquidityReturnDelta: false
```

## Important Notes

1. **FHE Limitations**: While `depositToken0` succeeded and stored an encrypted hash, actual FHE operations (encryption, decryption, computation) require Fhenix precompiles and cannot function on Sepolia.

2. **Residual Routing**: The hook structure for residual routing is in place, but full functionality requires FHE operations to match directions and route amounts.

3. **Testing**: Use the provided cast scripts:
   ```bash
   bash scripts/cast-interactions.sh
   bash scripts/cast-fhe-attempts.sh
   ```

4. **For Full Functionality**: Deploy to Fhenix testnet (Nitrogen) where FHE precompiles are available.

## Explorer Links

- [PrivacyHook on Sepolia Etherscan](https://sepolia.etherscan.io/address/0x72Acb50A8a6C7d39b08C56558fdeFfaF7C2b885A)
- [Token0 on Sepolia Etherscan](https://sepolia.etherscan.io/address/0xd458768065296912E75C7962c7fF502FB85A5255)
- [Token1 on Sepolia Etherscan](https://sepolia.etherscan.io/address/0x9c14e6351eB6a0526EDB6c798bE3a51fF26E1a59)


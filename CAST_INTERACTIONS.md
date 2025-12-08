# Cast Interactions with PrivacyHook on Sepolia

## Deployment Summary

**Contract Addresses (Sepolia):**
- PrivacyHook: `0x72Acb50A8a6C7d39b08C56558fdeFfaF7C2b885A`
- HybridFHERC20 Token0: `0xd458768065296912E75C7962c7fF502FB85A5255`
- HybridFHERC20 Token1: `0x9c14e6351eB6a0526EDB6c798bE3a51fF26E1a59`
- Deployer: `0x4b992F2Fbf714C0fCBb23baC5130Ace48CaD00cd`

## Working Functions (Non-FHE)

### View Functions

```bash
# Hook state
cast call 0x72Acb50A8a6C7d39b08C56558fdeFfaF7C2b885A "relayer()(address)" --rpc-url $SEPOLIA_RPC_URL
cast call 0x72Acb50A8a6C7d39b08C56558fdeFfaF7C2b885A "poolManager()(address)" --rpc-url $SEPOLIA_RPC_URL
cast call 0x72Acb50A8a6C7d39b08C56558fdeFfaF7C2b885A "token0()(address)" --rpc-url $SEPOLIA_RPC_URL
cast call 0x72Acb50A8a6C7d39b08C56558fdeFfaF7C2b885A "token1()(address)" --rpc-url $SEPOLIA_RPC_URL
cast call 0x72Acb50A8a6C7d39b08C56558fdeFfaF7C2b885A "isIntentActive(address)(bool)" $DEPLOYER --rpc-url $SEPOLIA_RPC_URL
cast call 0x72Acb50A8a6C7d39b08C56558fdeFfaF7C2b885A "getHookPermissions()((bool,bool,bool,bool,bool,bool,bool,bool,bool,bool,bool,bool,bool))" --rpc-url $SEPOLIA_RPC_URL

# Token state
cast call 0xd458768065296912E75C7962c7fF502FB85A5255 "name()(string)" --rpc-url $SEPOLIA_RPC_URL
cast call 0xd458768065296912E75C7962c7fF502FB85A5255 "symbol()(string)" --rpc-url $SEPOLIA_RPC_URL
cast call 0xd458768065296912E75C7962c7fF502FB85A5255 "balanceOf(address)(uint256)" $DEPLOYER --rpc-url $SEPOLIA_RPC_URL
```

### Public Token Operations

```bash
# Mint tokens
cast send 0xd458768065296912E75C7962c7fF502FB85A5255 "mint(address,uint256)" $DEPLOYER 100000000000000000000 --private-key $PRIVATE_KEY --rpc-url $SEPOLIA_RPC_URL

# Approve hook
cast send 0xd458768065296912E75C7962c7fF502FB85A5255 "approve(address,uint256)" 0x72Acb50A8a6C7d39b08C56558fdeFfaF7C2b885A 1000000000000000000000000000000000000000000000000000000000000 --private-key $PRIVATE_KEY --rpc-url $SEPOLIA_RPC_URL

# Cancel intent (no FHE required)
cast send 0x72Acb50A8a6C7d39b08C56558fdeFfaF7C2b885A "cancelIntent()" --private-key $PRIVATE_KEY --rpc-url $SEPOLIA_RPC_URL
```

## Non-Working Functions (FHE Required)

### FHE Functions That Fail on Sepolia

These functions require Fhenix FHE precompiles and **cannot work on Sepolia**:

1. **`depositToken0/1(uint128)`** - Requires FHE encryption internally
2. **`submitIntent(InEuint128, InEbool)`** - Requires FHE types
3. **`settleMatched(address, address, InEuint128)`** - Requires FHE types + relayer
4. **`requestWithdrawToken0/1(InEuint128)`** - Requires FHE types
5. **`finalizeWithdrawToken0/1(euint128)`** - Requires FHE decryption

### Attempting FHE Functions (Will Fail)

```bash
# These will revert on Sepolia
cast send 0x72Acb50A8a6C7d39b08C56558fdeFfaF7C2b885A "depositToken0(uint128)" 10000000000000000000 --private-key $PRIVATE_KEY --rpc-url $SEPOLIA_RPC_URL
# Error: FHE precompiles not available

# Reading encrypted values returns hashes (not usable)
cast call 0xd458768065296912E75C7962c7fF502FB85A5255 "encBalances(address)(uint256)" $DEPLOYER --rpc-url $SEPOLIA_RPC_URL
# Returns: encrypted hash (not decryptable without FHE)
```

## Running the Interaction Scripts

```bash
# Run all non-FHE interactions
bash scripts/cast-interactions.sh

# Attempt FHE function calls (will fail)
bash scripts/cast-fhe-attempts.sh
```

## Summary

**✅ Working on Sepolia:**
- View functions (read state)
- Public token operations (mint, approve, transfer)
- Intent cancellation
- Hook permissions check

**❌ Not Working on Sepolia:**
- All FHE operations (deposit, submitIntent, settleMatched, withdraw)
- Encrypted balance reads (returns hashes, not usable)
- Residual routing (requires FHE operations)

**To test FHE functions, deploy to Fhenix testnet!**


# Contract Verification on Etherscan

## PrivacyHook Contract

**Address:** `0x72Acb50A8a6C7d39b08C56558fdeFfaF7C2b885A`  
**Network:** Sepolia Testnet

## Constructor Arguments

```
PoolManager: 0x61b3f2011a92d183c7dbadbda940a7555ccf9227
Relayer:      0x4b992F2Fbf714C0fCBb23baC5130Ace48CaD00cd
Token0:       0xd458768065296912E75C7962c7fF502FB85A5255
Token1:       0x9c14e6351eB6a0526EDB6c798bE3a51fF26E1a59
```

**ABI-encoded Constructor Arguments:**
```
0x00000000000000000000000061b3f2011a92d183c7dbadbda940a7555ccf92270000000000000000000000004b992f2fbf714c0fcbb23bac5130ace48cad00cd000000000000000000000000d458768065296912e75c7962c7ff502fb85a52550000000000000000000000009c14e6351eb6a0526edb6c798be3a51ff26e1a59
```

## Verification Methods

### Method 1: Manual Verification (Recommended)

1. Go to [Sepolia Etherscan](https://sepolia.etherscan.io/address/0x72Acb50A8a6C7d39b08C56558fdeFfaF7C2b885A#code)
2. Click **"Verify and Publish"**
3. Select **"Via Standard JSON Input"**
4. Fill in the following:
   - **Compiler Type:** Solidity (Single file)
   - **Compiler Version:** `v0.8.26+commit.8aa97cc7`
   - **EVM Version:** `Cancun`
   - **License:** MIT
5. Upload the flattened source code from `docs/PrivacyHook.flattened.sol`
6. Paste the ABI-encoded constructor arguments above
7. Click **"Verify and Publish"**

### Method 2: Using Hardhat (Currently Failing - API V2 Migration)

The Hardhat verify plugin is currently using the deprecated V1 API. To use it once updated:

```bash
npx hardhat run scripts/verify-hook-sepolia.ts --network sepolia
```

### Method 3: Using Foundry Cast (Alternative)

```bash
# Generate flattened source
forge flatten src/PrivacyHook.sol --output docs/PrivacyHook.flattened.sol

# Then use Etherscan UI with the flattened source
```

## Compiler Settings

- **Solidity Version:** `0.8.26`
- **EVM Version:** `Cancun`
- **Optimization:** Enabled (via IR)
- **Optimizer Runs:** 200

## Dependencies

The contract imports:
- `@uniswap/v4-core`
- `@uniswap/v4-periphery`
- `@fhenixprotocol/cofhe-contracts`
- `@openzeppelin/contracts`

These are included in the flattened source file.

## Verification Status

- [ ] PrivacyHook - Pending verification
- [ ] HybridFHERC20 Token0 - Not verified
- [ ] HybridFHERC20 Token1 - Not verified

## Notes

- The Hardhat verify plugin currently fails due to Etherscan API V2 migration
- Manual verification via Etherscan UI is the most reliable method
- The flattened source code is available in `docs/PrivacyHook.flattened.sol`


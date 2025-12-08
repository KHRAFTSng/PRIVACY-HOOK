# Contract Verification Summary

## PrivacyHook Contract Verification

**Contract Address:** `0x72Acb50A8a6C7d39b08C56558fdeFfaF7C2b885A`  
**Network:** Sepolia Testnet  
**Etherscan:** https://sepolia.etherscan.io/address/0x72Acb50A8a6C7d39b08C56558fdeFfaF7C2b885A

## Quick Verification Steps

### Option 1: Manual Verification (Easiest)

1. Visit: https://sepolia.etherscan.io/address/0x72Acb50A8a6C7d39b08C56558fdeFfaF7C2b885A#code
2. Click **"Contract"** tab → **"Verify and Publish"**
3. Select **"Via Standard JSON Input"**
4. Use these settings:
   - **Compiler:** `v0.8.26+commit.8aa97cc7`
   - **EVM Version:** `cancun`
   - **License:** MIT
5. Upload `docs/PrivacyHook.flattened.sol`
6. Constructor arguments (ABI-encoded):
   ```
   0x00000000000000000000000061b3f2011a92d183c7dbadbda940a7555ccf92270000000000000000000000004b992f2fbf714c0fcbb23bac5130ace48cad00cd000000000000000000000000d458768065296912e75c7962c7ff502fb85a52550000000000000000000000009c14e6351eb6a0526edb6c798be3a51ff26e1a59
   ```
7. Click **"Verify and Publish"**

### Option 2: Automated (When API V2 Support Available)

The Hardhat verify plugin currently requires Etherscan API V2 migration. Once updated:

```bash
npx hardhat run scripts/verify-hook-sepolia.ts --network sepolia
```

## Constructor Parameters

| Parameter | Address |
|-----------|---------|
| PoolManager | `0x61b3f2011a92d183c7dbadbda940a7555ccf9227` |
| Relayer | `0x4b992F2Fbf714C0fCBb23baC5130Ace48CaD00cd` |
| Token0 | `0xd458768065296912E75C7962c7fF502FB85A5255` |
| Token1 | `0x9c14e6351eB6a0526EDB6c798bE3a51fF26E1a59` |

## Files Prepared

- ✅ Flattened source: `docs/PrivacyHook.flattened.sol`
- ✅ Constructor args: ABI-encoded (see above)
- ✅ Verification script: `scripts/verify-hook-sepolia.ts`
- ✅ Documentation: `docs/VERIFICATION.md`

## Status

- [x] Contract deployed
- [x] Flattened source generated
- [x] Constructor args prepared
- [ ] Contract verified on Etherscan (pending manual verification)

## Next Steps

1. Complete manual verification using the steps above
2. Once verified, update this document with the verification status
3. Share the verified contract link


#!/bin/bash
# Direct Etherscan API verification for PrivacyHook

set -e

HOOK_ADDRESS="0x72Acb50A8a6C7d39b08C56558fdeFfaF7C2b885A"
API_KEY="${ETHERSCAN_API_KEY:-PRPS7NDEPG461YQJ92AUEFSAKZIZT7EMWM}"
POOL_MANAGER="0x61b3f2011a92d183c7dbadbda940a7555ccf9227"
RELAYER="0x4b992F2Fbf714C0fCBb23baC5130Ace48CaD00cd"
TOKEN0="0xd458768065296912E75C7962c7fF502FB85A5255"
TOKEN1="0x9c14e6351eB6a0526EDB6c798bE3a51fF26E1a59"

# Get source code
SOURCE_CODE=$(cat <<EOF
// SPDX-License-Identifier: MIT
// This file contains flattened source code - use hardhat flatten or similar
EOF
)

echo "Attempting direct Etherscan verification..."
echo "Note: This requires flattened source code"
echo ""
echo "For now, use the manual verification on Etherscan:"
echo "1. Go to: https://sepolia.etherscan.io/address/$HOOK_ADDRESS#code"
echo "2. Click 'Verify and Publish'"
echo "3. Select 'Via Standard JSON Input'"
echo "4. Compiler: 0.8.26"
echo "5. EVM Version: Cancun"
echo "6. Constructor Arguments (ABI-encoded):"
cast abi-encode "constructor(address,address,address,address)" \
    "$POOL_MANAGER" \
    "$RELAYER" \
    "$TOKEN0" \
    "$TOKEN1"
echo ""
echo "Or use Hardhat flatten to get the full source:"
echo "npx hardhat flatten src/PrivacyHook.sol > PrivacyHook.flattened.sol"


#!/bin/bash
# Attempts to interact with FHE functions using cast
# These will fail on Sepolia but demonstrate the structure

set -e

HOOK="0x72Acb50A8a6C7d39b08C56558fdeFfaF7C2b885A"
TOKEN0="0xd458768065296912E75C7962c7fF502FB85A5255"
TOKEN1="0x9c14e6351eB6a0526EDB6c798bE3a51fF26E1a59"
DEPLOYER="0x4b992F2Fbf714C0fCBb23baC5130Ace48CaD00cd"
RPC_URL="${SEPOLIA_RPC_URL:-https://eth-sepolia.g.alchemy.com/v2/FlEUrYqZ9gYvgFxtEVA6zWB0zrQwGL4N}"
PRIVATE_KEY="${PRIVATE_KEY:-0x885193e06bfcfbff6348f1b9caf486a18c2b927e66382223d7c1cafa9858bb72}"

echo "=========================================="
echo "FHE Function Interaction Attempts"
echo "=========================================="
echo "Note: These will fail on Sepolia (no FHE precompiles)"
echo ""

# Attempt to read encrypted balance (will fail)
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Attempt: Read encrypted balance"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cast call $TOKEN0 "encBalances(address)(uint256)" $DEPLOYER --rpc-url $RPC_URL || echo "✗ Failed (expected - returns encrypted hash, not usable without FHE)"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Attempt: Read total encrypted supply"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cast call $TOKEN0 "totalEncryptedSupply()(uint256)" --rpc-url $RPC_URL || echo "✗ Failed (expected - returns encrypted hash)"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Attempt: Read intent amount (encrypted)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cast call $HOOK "intents(address)(uint256,bool,bool)" $DEPLOYER --rpc-url $RPC_URL || echo "✗ Failed (expected - struct with encrypted values)"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Attempt: Read residual amount (encrypted)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cast call $HOOK "residuals(address)(uint256,bool,bool)" $DEPLOYER --rpc-url $RPC_URL || echo "✗ Failed (expected - struct with encrypted values)"

echo ""
echo "=========================================="
echo "FHE Function Signatures (for reference)"
echo "=========================================="
echo ""
echo "submitIntent(InEuint128 amount, InEbool zeroForOne)"
echo "  - Requires FHE encryption to create InEuint128/InEbool"
echo "  - Cannot be called on Sepolia"
echo ""
echo "settleMatched(address maker, address taker, InEuint128 matchedAmount)"
echo "  - Requires FHE encryption and relayer permission"
echo "  - Cannot be called on Sepolia"
echo ""
echo "requestWithdrawToken0/1(InEuint128 encAmount)"
echo "  - Requires FHE encryption"
echo "  - Cannot be called on Sepolia"
echo ""
echo "=========================================="


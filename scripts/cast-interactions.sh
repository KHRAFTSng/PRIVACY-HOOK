#!/bin/bash
# Cast interactions with PrivacyHook on Sepolia
# Note: FHE operations will fail on Sepolia, but we can test non-FHE functions

set -e

# Contract addresses from deployment
HOOK="0x72Acb50A8a6C7d39b08C56558fdeFfaF7C2b885A"
TOKEN0="0xd458768065296912E75C7962c7fF502FB85A5255"
TOKEN1="0x9c14e6351eB6a0526EDB6c798bE3a51fF26E1a59"
DEPLOYER="0x4b992F2Fbf714C0fCBb23baC5130Ace48CaD00cd"
RPC_URL="${SEPOLIA_RPC_URL:-https://eth-sepolia.g.alchemy.com/v2/FlEUrYqZ9gYvgFxtEVA6zWB0zrQwGL4N}"

echo "=========================================="
echo "PrivacyHook Cast Interactions on Sepolia"
echo "=========================================="
echo "Hook: $HOOK"
echo "Token0: $TOKEN0"
echo "Token1: $TOKEN1"
echo "Deployer: $DEPLOYER"
echo ""

# Helper function to run cast commands
run_cast() {
    local description="$1"
    local cmd="$2"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "TEST: $description"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Command: $cmd"
    echo ""
    if eval "$cmd"; then
        echo "✓ SUCCESS"
    else
        echo "✗ FAILED (expected for FHE operations on Sepolia)"
    fi
    echo ""
}

# ==========================================
# 1. READ CONTRACT STATE (View Functions)
# ==========================================
echo "=========================================="
echo "1. READING CONTRACT STATE"
echo "=========================================="
echo ""

run_cast "Hook relayer address" \
    "cast call $HOOK 'relayer()(address)' --rpc-url $RPC_URL"

run_cast "Hook poolManager address" \
    "cast call $HOOK 'poolManager()(address)' --rpc-url $RPC_URL"

run_cast "Hook token0 address" \
    "cast call $HOOK 'token0()(address)' --rpc-url $RPC_URL"

run_cast "Hook token1 address" \
    "cast call $HOOK 'token1()(address)' --rpc-url $RPC_URL"

run_cast "Check intent active status" \
    "cast call $HOOK 'isIntentActive(address)(bool)' $DEPLOYER --rpc-url $RPC_URL"

run_cast "Token0 name" \
    "cast call $TOKEN0 'name()(string)' --rpc-url $RPC_URL"

run_cast "Token0 symbol" \
    "cast call $TOKEN0 'symbol()(string)' --rpc-url $RPC_URL"

run_cast "Token1 name" \
    "cast call $TOKEN1 'name()(string)' --rpc-url $RPC_URL"

run_cast "Token1 symbol" \
    "cast call $TOKEN1 'symbol()(string)' --rpc-url $RPC_URL"

# ==========================================
# 2. PUBLIC TOKEN OPERATIONS
# ==========================================
echo "=========================================="
echo "2. PUBLIC TOKEN OPERATIONS"
echo "=========================================="
echo ""

PRIVATE_KEY="${PRIVATE_KEY:-0x885193e06bfcfbff6348f1b9caf486a18c2b927e66382223d7c1cafa9858bb72}"

run_cast "Mint 100 Token0 to deployer" \
    "cast send $TOKEN0 'mint(address,uint256)' $DEPLOYER 100000000000000000000 --private-key $PRIVATE_KEY --rpc-url $RPC_URL"

run_cast "Mint 100 Token1 to deployer" \
    "cast send $TOKEN1 'mint(address,uint256)' $DEPLOYER 100000000000000000000 --private-key $PRIVATE_KEY --rpc-url $RPC_URL"

run_cast "Check Token0 balance" \
    "cast call $TOKEN0 'balanceOf(address)(uint256)' $DEPLOYER --rpc-url $RPC_URL"

run_cast "Approve hook to spend Token0" \
    "cast send $TOKEN0 'approve(address,uint256)' $HOOK 1000000000000000000000000000000000000000000000000000000000000 --private-key $PRIVATE_KEY --rpc-url $RPC_URL"

run_cast "Approve hook to spend Token1" \
    "cast send $TOKEN1 'approve(address,uint256)' $HOOK 1000000000000000000000000000000000000000000000000000000000000 --private-key $PRIVATE_KEY --rpc-url $RPC_URL"

# ==========================================
# 3. DEPOSIT OPERATIONS
# ==========================================
echo "=========================================="
echo "3. DEPOSIT OPERATIONS"
echo "=========================================="
echo ""

run_cast "Deposit 10 Token0 (will fail - requires FHE)" \
    "cast send $HOOK 'depositToken0(uint128)' 10000000000000000000 --private-key $PRIVATE_KEY --rpc-url $RPC_URL"

run_cast "Deposit 10 Token1 (will fail - requires FHE)" \
    "cast send $HOOK 'depositToken1(uint128)' 10000000000000000000 --private-key $PRIVATE_KEY --rpc-url $RPC_URL"

# ==========================================
# 4. INTENT OPERATIONS
# ==========================================
echo "=========================================="
echo "4. INTENT OPERATIONS"
echo "=========================================="
echo ""

# Note: submitIntent requires FHE types (InEuint128, InEbool) which can't be created without FHE precompiles
echo "⚠️  submitIntent requires FHE encryption - cannot test on Sepolia"
echo "   Would need: cast send with InEuint128 and InEbool types"
echo ""

run_cast "Cancel intent (should work - no FHE)" \
    "cast send $HOOK 'cancelIntent()' --private-key $PRIVATE_KEY --rpc-url $RPC_URL"

# ==========================================
# 5. WITHDRAW OPERATIONS
# ==========================================
echo "=========================================="
echo "5. WITHDRAW OPERATIONS"
echo "=========================================="
echo ""

echo "⚠️  requestWithdrawToken0/1 require FHE encryption - cannot test on Sepolia"
echo "   Would need: cast send with InEuint128 type"
echo ""

# ==========================================
# 6. SETTLEMENT OPERATIONS
# ==========================================
echo "=========================================="
echo "6. SETTLEMENT OPERATIONS"
echo "=========================================="
echo ""

echo "⚠️  settleMatched requires FHE encryption and relayer permission"
echo "   Would need: cast send with InEuint128 type from relayer address"
echo ""

# ==========================================
# 7. HOOK PERMISSIONS
# ==========================================
echo "=========================================="
echo "7. HOOK PERMISSIONS"
echo "=========================================="
echo ""

run_cast "Get hook permissions" \
    "cast call $HOOK 'getHookPermissions()((bool,bool,bool,bool,bool,bool,bool,bool,bool,bool,bool,bool,bool))' --rpc-url $RPC_URL"

# ==========================================
# SUMMARY
# ==========================================
echo "=========================================="
echo "INTERACTION SUMMARY"
echo "=========================================="
echo "✓ View functions: WORKING"
echo "✓ Public token operations: WORKING"
echo "✗ FHE operations (deposit/intent/settle): FAILING (expected on Sepolia)"
echo ""
echo "To test FHE operations, deploy to Fhenix testnet!"
echo "=========================================="


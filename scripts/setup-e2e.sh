#!/bin/bash
# Setup script for E2E testing with localfhenix

set -e

echo "🔧 Privacy Hook E2E Setup"
echo "=========================="
echo ""

# Check if localfhenix is running
echo "1. Checking if localfhenix is running..."
if curl -s http://localhost:42000 > /dev/null 2>&1; then
    echo "✅ localfhenix is running"
else
    echo "❌ localfhenix is not running"
    echo ""
    echo "Please start localfhenix first:"
    echo "  Option 1: Install and run via Docker (if available)"
    echo "  Option 2: Install via: npm install -g localfhenix (check Fhenix docs for correct package)"
    echo "  Option 3: Use Fhenix Nitrogen testnet (update .env with testnet RPC)"
    echo ""
    exit 1
fi

echo ""
echo "2. Deploying contracts..."
npx hardhat run scripts/deploy-privacy.ts --network fhenix

echo ""
echo "3. Copy the addresses above to frontend/packages/nextjs/.env.local"
echo ""
echo "4. Start frontend:"
echo "   cd frontend && yarn dev"
echo ""


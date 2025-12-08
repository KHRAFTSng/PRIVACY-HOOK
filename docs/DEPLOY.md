# Deployment Guide

## Prerequisites

1. **Start localfhenix** (for local testing):
   ```bash
   # Install localfhenix if needed
   npm install -g @fhenixprotocol/localfhenix
   
   # Start localfhenix node
   localfhenix
   ```
   This will start a local Fhenix node at `http://localhost:42000` with chain ID `420105`.

2. **Or use Fhenix Nitrogen testnet**:
   - RPC: `https://api.nitrogen.fhenix.zone`
   - Chain ID: `42069`
   - Get testnet tokens from faucet

## Setup Environment

1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` with your values:
   - `FHENIX_RPC_URL`: Your Fhenix RPC endpoint
   - `FHENIX_PRIVATE_KEY`: Deployer private key (must be funded)
   - `FHENIX_RELAYER`: Address allowed to call `settleMatched`
   - `FHENIX_POOL_MANAGER`: PoolManager address (placeholder `0x0000...0001` if not using v4 swaps)

## Deploy Contracts

```bash
npx hardhat run scripts/deploy-privacy.ts --network fhenix
```

This will output:
```
NEXT_PUBLIC_PRIVACY_HOOK_ADDRESS=0x...
NEXT_PUBLIC_PRIVACY_TOKEN0_ADDRESS=0x...
NEXT_PUBLIC_PRIVACY_TOKEN1_ADDRESS=0x...
```

## Setup Frontend

1. Copy the output addresses to `frontend/packages/nextjs/.env.local`:
   ```bash
   NEXT_PUBLIC_PRIVACY_HOOK_ADDRESS=0x...
   NEXT_PUBLIC_PRIVACY_TOKEN0_ADDRESS=0x...
   NEXT_PUBLIC_PRIVACY_TOKEN1_ADDRESS=0x...
   ```

2. Start the frontend:
   ```bash
   cd frontend
   yarn dev
   ```

## Testing the Flow

1. **Deposit tokens**: Use the UI to deposit token0/token1 (wraps to encrypted balances)
2. **Submit intent**: Submit an encrypted trade intent (amount + direction)
3. **Settle matched**: As relayer, call `settleMatched` to execute matched trades
4. **View balances**: Check encrypted balances (requires FHE permissions)


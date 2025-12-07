*PRIVACY HOOK*

Privacy Hook: Encrypted Intent-Based Trading for Uniswap V4
Brief Description
Privacy Hook is a privacy-first Uniswap V4 hook that enables completely encrypted swaps using Fhenix's Fully Homomorphic Encryption (FHE). Users deposit tokens to receive encrypted balance tokens (ERC7984), then submit trade intents where amounts, directions, and order sizes are fully hidden on-chain. A relayer matches opposing intents off-chain and settles them in batches: matched trades execute as internal encrypted transfers with zero fees and no slippage, while only the net unmatched volume routes through the AMM. Idle liquidity automatically earns yield via integrated lending protocols (SimpleLending), shuttled just-in-time during swaps for maximum capital efficiency.

The Problem (One Sentence)
Public mempool transparency exposes traders to MEV extraction, frontrunning, and information leakage—especially devastating for large orders where even seeing the trade direction or size allows exploitation.

The Solution (One Sentence)
Encrypt everything end-to-end using Fhenix FHE so that trade amounts, directions, and balances remain hidden even from the contract itself, with matched intents settling internally (no AMM fees) and only net residuals touching Uniswap pools.

Key Innovation
Triple Privacy Architecture powered by Fhenix:

Encrypted Balances (ERC7984): Token balances encrypted as euint64 using Fhenix FHE, invisible to everyone
Encrypted Intents: Trade amounts AND directions encrypted (euint64 + euint8), zero information leakage
Off-Chain Matching: Relayer with FHE permissions matches opposite trades privately using Fhenix's confidential compute, only settlement data touches chain

Result: MEV bots can't see what you're trading, how much you're trading, or which direction—making frontrunning mathematically impossible thanks to Fhenix's onchain FHE.

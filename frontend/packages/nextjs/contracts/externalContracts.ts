import { GenericContractsDeclaration } from "~~/utils/scaffold-eth/contract";

const hookAddress = process.env.NEXT_PUBLIC_PRIVACY_HOOK_ADDRESS || "0x0000000000000000000000000000000000000000";
const token0Address = process.env.NEXT_PUBLIC_PRIVACY_TOKEN0_ADDRESS || "0x0000000000000000000000000000000000000000";
const token1Address = process.env.NEXT_PUBLIC_PRIVACY_TOKEN1_ADDRESS || "0x0000000000000000000000000000000000000000";

/**
 * @example
 * const externalContracts = {
 *   1: {
 *     DAI: {
 *       address: "0x...",
 *       abi: [...],
 *     },
 *   },
 * } as const;
 */
const externalContracts = {
  31337: {
    PrivacyHook: {
      address: hookAddress as `0x${string}`,
      abi: [
        {
          inputs: [{ internalType: "uint128", name: "amount", type: "uint128" }],
          name: "depositToken0",
          outputs: [],
          stateMutability: "nonpayable",
          type: "function",
        },
        {
          inputs: [{ internalType: "uint128", name: "amount", type: "uint128" }],
          name: "depositToken1",
          outputs: [],
          stateMutability: "nonpayable",
          type: "function",
        },
        {
          inputs: [
            { components: [{ internalType: "uint256", name: "data", type: "uint256" }], internalType: "struct InEuint128", name: "amount", type: "tuple" },
            { components: [{ internalType: "uint256", name: "data", type: "uint256" }], internalType: "struct InEbool", name: "zeroForOne", type: "tuple" },
          ],
          name: "submitIntent",
          outputs: [],
          stateMutability: "nonpayable",
          type: "function",
        },
        {
          inputs: [
            { internalType: "address", name: "maker", type: "address" },
            { internalType: "address", name: "taker", type: "address" },
            { components: [{ internalType: "uint256", name: "data", type: "uint256" }], internalType: "struct InEuint128", name: "matchedAmount", type: "tuple" },
          ],
          name: "settleMatched",
          outputs: [],
          stateMutability: "nonpayable",
          type: "function",
        },
        {
          inputs: [{ internalType: "address", name: "user", type: "address" }],
          name: "isIntentActive",
          outputs: [{ internalType: "bool", name: "", type: "bool" }],
          stateMutability: "view",
          type: "function",
        },
      ],
    },
    HybridFHERC20: {
      address: token0Address as `0x${string}`,
      abi: [
        {
          inputs: [{ internalType: "address", name: "user", type: "address" }, { internalType: "uint128", name: "amount", type: "uint128" }],
          name: "wrap",
          outputs: [],
          stateMutability: "nonpayable",
          type: "function",
        },
        {
          inputs: [{ internalType: "address", name: "user", type: "address" }, { components: [{ internalType: "uint256", name: "data", type: "uint256" }], internalType: "struct InEuint128", name: "amount", type: "tuple" }],
          name: "requestUnwrap",
          outputs: [{ internalType: "euint128", name: "", type: "uint256" }],
          stateMutability: "nonpayable",
          type: "function",
        },
        {
          inputs: [{ internalType: "address", name: "user", type: "address" }, { internalType: "euint128", name: "burnAmount", type: "uint256" }],
          name: "getUnwrapResult",
          outputs: [{ internalType: "uint128", name: "amount", type: "uint128" }],
          stateMutability: "nonpayable",
          type: "function",
        },
        {
          inputs: [{ internalType: "address", name: "", type: "address" }],
          name: "encBalances",
          outputs: [{ internalType: "uint256", name: "", type: "uint256" }],
          stateMutability: "view",
          type: "function",
        },
      ],
    },
    HybridFHERC20Token1: {
      address: token1Address as `0x${string}`,
      abi: [
        {
          inputs: [{ internalType: "address", name: "user", type: "address" }, { internalType: "uint128", name: "amount", type: "uint128" }],
          name: "wrap",
          outputs: [],
          stateMutability: "nonpayable",
          type: "function",
        },
        {
          inputs: [{ internalType: "address", name: "user", type: "address" }, { components: [{ internalType: "uint256", name: "data", type: "uint256" }], internalType: "struct InEuint128", name: "amount", type: "tuple" }],
          name: "requestUnwrap",
          outputs: [{ internalType: "euint128", name: "", type: "uint256" }],
          stateMutability: "nonpayable",
          type: "function",
        },
        {
          inputs: [{ internalType: "address", name: "user", type: "address" }, { internalType: "euint128", name: "burnAmount", type: "uint256" }],
          name: "getUnwrapResult",
          outputs: [{ internalType: "uint128", name: "amount", type: "uint128" }],
          stateMutability: "nonpayable",
          type: "function",
        },
        {
          inputs: [{ internalType: "address", name: "", type: "address" }],
          name: "encBalances",
          outputs: [{ internalType: "uint256", name: "", type: "uint256" }],
          stateMutability: "view",
          type: "function",
        },
      ],
    },
  },
} as const;

export default externalContracts satisfies GenericContractsDeclaration;

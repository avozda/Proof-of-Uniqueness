// Smart contract ABI for IdentityVerification
export const identityVerificationABI = [
  {
    type: "constructor",
    inputs: [{ name: "_root", type: "uint256", internalType: "uint256" }],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "insertHashID",
    inputs: [
      { name: "_pA", type: "uint256[2]", internalType: "uint256[2]" },
      { name: "_pB", type: "uint256[2][2]", internalType: "uint256[2][2]" },
      { name: "_pC", type: "uint256[2]", internalType: "uint256[2]" },
      { name: "_pubSignals", type: "uint256[1]", internalType: "uint256[1]" },
      { name: "_pA_smt", type: "uint256[2]", internalType: "uint256[2]" },
      { name: "_pB_smt", type: "uint256[2][2]", internalType: "uint256[2][2]" },
      { name: "_pC_smt", type: "uint256[2]", internalType: "uint256[2]" },
      {
        name: "_pubSignals_smt",
        type: "uint256[3]",
        internalType: "uint256[3]",
      },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "root",
    inputs: [],
    outputs: [{ name: "", type: "uint256", internalType: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "verify",
    inputs: [
      { name: "_pA", type: "uint256[2]", internalType: "uint256[2]" },
      { name: "_pB", type: "uint256[2][2]", internalType: "uint256[2][2]" },
      { name: "_pC", type: "uint256[2]", internalType: "uint256[2]" },
      { name: "_pubSignals", type: "uint256[1]", internalType: "uint256[1]" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "verifyHashIdProof",
    inputs: [
      { name: "_pA", type: "uint256[2]", internalType: "uint256[2]" },
      { name: "_pB", type: "uint256[2][2]", internalType: "uint256[2][2]" },
      { name: "_pC", type: "uint256[2]", internalType: "uint256[2]" },
      { name: "_pubSignals", type: "uint256[1]", internalType: "uint256[1]" },
    ],
    outputs: [{ name: "", type: "bool", internalType: "bool" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "verifySMTProof",
    inputs: [
      { name: "_pA", type: "uint256[2]", internalType: "uint256[2]" },
      { name: "_pB", type: "uint256[2][2]", internalType: "uint256[2][2]" },
      { name: "_pC", type: "uint256[2]", internalType: "uint256[2]" },
      { name: "_pubSignals", type: "uint256[3]", internalType: "uint256[3]" },
    ],
    outputs: [{ name: "", type: "bool", internalType: "bool" }],
    stateMutability: "view",
  },
  {
    type: "event",
    name: "HashIDClaim",
    inputs: [
      {
        name: "_pA",
        type: "uint256[2]",
        indexed: false,
        internalType: "uint256[2]",
      },
      {
        name: "_pB",
        type: "uint256[2][2]",
        indexed: false,
        internalType: "uint256[2][2]",
      },
      {
        name: "_pC",
        type: "uint256[2]",
        indexed: false,
        internalType: "uint256[2]",
      },
      {
        name: "_pubSignals",
        type: "uint256[1]",
        indexed: false,
        internalType: "uint256[1]",
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "HashIDInserted",
    inputs: [
      {
        name: "hashID",
        type: "uint256",
        indexed: false,
        internalType: "uint256",
      },
      {
        name: "newRoot",
        type: "uint256",
        indexed: false,
        internalType: "uint256",
      },
    ],
    anonymous: false,
  },
] as const;

// Contract addresses (placeholders - replace with actual deployed addresses)
export const contractAddresses = {
  identityVerification:
    "0x5FbDB2315678afecb367f032d93F642f64180aa3" as `0x${string}`,
  // Add more contract addresses as needed
  sepolia: "0x0000000000000000000000000000000000000000" as `0x${string}`,
  mainnet: "0x0000000000000000000000000000000000000000" as `0x${string}`,
  anvil: "0x5FbDB2315678afecb367f032d93F642f64180aa3" as `0x${string}`,
} as const;

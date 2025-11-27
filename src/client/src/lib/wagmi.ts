import { http, createConfig } from "wagmi";
import { defineChain } from "viem";
import { injected } from "wagmi/connectors";

// Define localhost chain (Anvil/Foundry default)
export const localhost = defineChain({
  id: 31337,
  name: "Localhost",
  nativeCurrency: {
    decimals: 18,
    name: "Ether",
    symbol: "ETH",
  },
  rpcUrls: {
    default: {
      http: ["http://127.0.0.1:8545"],
    },
  },
});

export const config = createConfig({
  chains: [localhost],
  connectors: [injected()],
  transports: {
    [localhost.id]: http(),
  },
});

// Contract addresses - update after deployment
export const CONTRACT_ADDRESSES = {
  proofOfUniqueness:
    "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512" as `0x${string}`,
  groth16Verifier:
    "0x5FbDB2315678afecb367f032d93F642f64180aa3" as `0x${string}`,
};

// Export function to update contract address at runtime
export function setContractAddress(address: `0x${string}`) {
  CONTRACT_ADDRESSES.proofOfUniqueness = address;
}

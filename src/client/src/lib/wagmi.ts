import { http, createConfig } from "wagmi";
import { defineChain } from "viem";
import { injected } from "wagmi/connectors";

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

export const CONTRACT_ADDRESSES = {
  identityRegistry:
    "0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0" as `0x${string}`,
  enrollmentVerifier:
    "0x5fbdb2315678afecb367f032d93f642f64180aa3" as `0x${string}`,
  revocationVerifier:
    "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512" as `0x${string}`,
};

export function setContractAddress(address: `0x${string}`) {
  CONTRACT_ADDRESSES.identityRegistry = address;
}

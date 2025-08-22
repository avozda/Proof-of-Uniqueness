import { http, createConfig } from "wagmi";

import { injected } from "wagmi/connectors";

const localhost = {
  id: 31337,
  name: "Localhost",
  network: "anvil",
  nativeCurrency: {
    decimals: 18,
    name: "Ether",
    symbol: "ETH",
  },
  rpcUrls: {
    default: { http: ["http://localhost:8545"] }, // Use localhost instead of 127.0.0.1
  },
};

export const config = createConfig({
  chains: [localhost],
  transports: {
    [localhost.id]: http("http://localhost:8545"), // Explicit HTTP URL
  },
  connectors: [
    injected({
      target: "metaMask",
    }),
  ],
});

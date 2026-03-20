import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { nodePolyfills } from "vite-plugin-node-polyfills";
import path from "path";

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react({
      babel: {
        plugins: [["babel-plugin-react-compiler"]],
      },
    }),
    // Polyfill Node.js built-ins for circomlibjs
    nodePolyfills({
      include: ["buffer", "crypto", "stream", "util", "process", "events"],
      globals: {
        Buffer: true,
        global: true,
        process: true,
      },
    }),
  ],
  resolve: {
    alias: {
      "ecdsa-fuzzy-signature": path.resolve(
        __dirname,
        "../ecdsa-fuzzy-signature/dist",
      ),
    },
  },
  optimizeDeps: {
    include: ["@noble/curves", "@noble/hashes", "circomlibjs"],
  },
});

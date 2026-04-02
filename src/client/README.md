# Client

React + TypeScript frontend for:

- VC generation
- enrollment proof generation/submission
- revocation proof generation/submission

## Commands

```bash
npm install
npm run dev
npm run build
```

## Important Paths

- Circuit artifacts loaded by browser: `public/circuits/`
- Contract ABI: `src/lib/contractAbi.ts`
- Contract address config: `src/lib/wagmi.ts`
- ZK flow UI: `src/components/ZKProofSection.tsx`

## Prerequisite

Build the local fuzzy package first:

```bash
cd ../EdDSA-fuzzy-signature
npm install
npm run build
```

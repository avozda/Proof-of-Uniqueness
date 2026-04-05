#!/usr/bin/env bash

set -euo pipefail

RPC_URL="${RPC_URL:-http://127.0.0.1:8545}"
OPRF_NODE_URL="${OPRF_NODE_URL:-http://127.0.0.1:10000}"
OPRF_KEY_ID="${OPRF_KEY_ID:-3}"
PRIVATE_KEY="${PRIVATE_KEY:-}"

if [[ -z "${PRIVATE_KEY}" ]]; then
  echo "error: PRIVATE_KEY is required"
  echo "example: PRIVATE_KEY=0xabc... $0"
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required but not installed"
  exit 1
fi

echo "Fetching OPRF public key from ${OPRF_NODE_URL}/oprf_pub/${OPRF_KEY_ID} ..."
OPRF_JSON="$(curl -sf "${OPRF_NODE_URL}/oprf_pub/${OPRF_KEY_ID}")"

OPRF_PUB_KEY_X="$(printf '%s' "${OPRF_JSON}" | jq -r '.key[0]')"
OPRF_PUB_KEY_Y="$(printf '%s' "${OPRF_JSON}" | jq -r '.key[1]')"
OPRF_EPOCH="$(printf '%s' "${OPRF_JSON}" | jq -r '.epoch // "unknown"')"

if [[ -z "${OPRF_PUB_KEY_X}" || -z "${OPRF_PUB_KEY_Y}" || "${OPRF_PUB_KEY_X}" == "null" || "${OPRF_PUB_KEY_Y}" == "null" ]]; then
  echo "error: failed to parse OPRF public key from node response"
  echo "response: ${OPRF_JSON}"
  exit 1
fi

echo "Using OPRF key id: ${OPRF_KEY_ID}"
echo "Using OPRF epoch : ${OPRF_EPOCH}"
echo "Using OPRF pk X  : ${OPRF_PUB_KEY_X}"
echo "Using OPRF pk Y  : ${OPRF_PUB_KEY_Y}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACTS_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "Deploying verifier + IdentityRegistry ..."
OPRF_PUB_KEY_X="${OPRF_PUB_KEY_X}" \
OPRF_PUB_KEY_Y="${OPRF_PUB_KEY_Y}" \
forge script "${CONTRACTS_DIR}/script/IdentityRegistry.s.sol:IdentityRegistryScript" \
  --rpc-url "${RPC_URL}" \
  --broadcast \
  --disable-code-size-limit \
  --private-key "${PRIVATE_KEY}"

echo "Done."

PRIVATE_KEY ?= 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
RPC_URL ?= http://127.0.0.1:8545
OPRF_NODE_URL ?= http://127.0.0.1:10000
OPRF_KEY_ID ?= 3

.PHONY: oprf-testnet network deploy web

oprf-testnet:
	cd src/oprf-testnet && chmod +x local-setup.sh && ./local-setup.sh setup

network:
	anvil --code-size-limit 50000

deploy:
	cd src/smart-contracts && \
	PRIVATE_KEY="$(PRIVATE_KEY)" \
	RPC_URL="$(RPC_URL)" \
	OPRF_NODE_URL="$(OPRF_NODE_URL)" \
	OPRF_KEY_ID="$(OPRF_KEY_ID)" \
	./script/deploy-identity-registry-dynamic-oprf.sh

web:
	cd src/client && npm install && npm run dev

#!/bin/bash
# Check quantum components only, excluding classic consensus

echo "Checking quantum components (excluding GRANDPA, BABE, Aura)..."

cargo check --workspace \
    --exclude sp-consensus-grandpa \
    --exclude sp-consensus-babe \
    --exclude sp-consensus-aura \
    --exclude sc-consensus-grandpa \
    --exclude sc-consensus-babe \
    --exclude sc-consensus-aura \
    --exclude sc-consensus-babe-rpc \
    --exclude sc-consensus-grandpa-rpc \
    --exclude polkadot-parachain-bin \
    --exclude polkadot-cli \
    --exclude polkadot \
    --exclude cumulus-relay-chain-consensus-aura \
    2>&1 | grep -v "workspace members are not all at the same version"
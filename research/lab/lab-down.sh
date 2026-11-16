#!/usr/bin/env bash
# Teardown of the Kryonsec research lab: removes the lab containers and
# networks (images are kept — they are digest-pinned references).
set -euo pipefail
docker rm -f juice-shop-lab kryonsec-lab-dns 2>/dev/null || true
docker network rm kryonsec-lab kryonsec-dns 2>/dev/null || true
echo "lab down"

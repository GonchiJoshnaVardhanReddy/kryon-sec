#!/usr/bin/env bash
# Kryonsec IEEE-research lab: bring up the isolated target + lab DNS.
#
# Infrastructure only — starts the target container, runs no security
# tools, sends no packets to any target. Scope, digests and reset
# procedure: see README.md. Teardown: ./lab-down.sh
set -euo pipefail
cd "$(dirname "$0")"

LAB_NET=kryonsec-lab;    LAB_SUBNET=10.213.43.0/24;  LAB_ICC=false
DNS_NET=kryonsec-dns;    DNS_SUBNET=10.213.44.0/24;  DNS_IP=10.213.44.1
TARGET_IP=10.213.43.10;  TARGET_ALIAS=juice-shop.lab; TARGET_NAME=juice-shop-lab
DNS_NAME=kryonsec-lab-dns
TARGET_IMAGE="$(cat images/juice-shop.image.txt)"   # digest-pinned reference

# Lab DNS: serves juice-shop.lab + webgoat.lab and forwards every other
# name to the pinned upstream (1.1.1.1). Docker 28/29 protect every
# container IP on NON-internal networks with a raw-table PREROUTING drop
# (-d <container-ip> ! -i <its-bridge> -j DROP), which would silently
# kill the sandbox's cross-bridge queries to a containerized resolver.
# So the resolver is HOST-owned: the container shares the host netns and
# binds ONLY the dns-bridge gateway IP (never eth0/WSL NAT). The sandbox
# reaches it through the gate's INPUT path — allow-only, dport 53 to the
# pinned resolver — and DNS answers never create connectivity.
docker build -q -t kryonsec-lab-dns:1 dnsmasq/ >/dev/null

if ! docker network inspect "$LAB_NET" >/dev/null 2>&1; then
  docker network create --internal --driver bridge \
    --subnet "$LAB_SUBNET" \
    --opt com.docker.network.bridge.enable_icc="$LAB_ICC" "$LAB_NET"
fi
if ! docker network inspect "$DNS_NET" >/dev/null 2>&1; then
  docker network create --driver bridge --subnet "$DNS_SUBNET" "$DNS_NET"
fi

docker rm -f "$DNS_NAME" >/dev/null 2>&1 || true
docker run -d --name "$DNS_NAME" --network host \
  --restart unless-stopped kryonsec-lab-dns:1 \
  --listen-address="$DNS_IP" --bind-interfaces

# Target: fresh container on every lab-up (no volumes — lab state is
# disposable by design). HTTP on port 80 because the deterministic
# recon pipeline uses a pinned port list and port-less URLs; PORT=80
# re-binds the app, and the unprivileged-port sysctl lets the
# non-root image user bind it.
docker rm -f "$TARGET_NAME" >/dev/null 2>&1 || true
docker run -d --name "$TARGET_NAME" --network "$LAB_NET" --ip "$TARGET_IP" \
  --network-alias "$TARGET_ALIAS" \
  --sysctl net.ipv4.ip_unprivileged_port_start=80 \
  -e PORT=80 \
  --restart unless-stopped "$TARGET_IMAGE"

# Second lab target (PREPARED, not yet in approved scope — do not aim
# tools at it until its scope is separately approved). WebGoat listens
# on 8080/9091 natively; 8080 is inside kryonsec's pinned discovery
# port list, so no port remap is needed. Fresh container = fresh state.
WEBGOAT_IP=10.213.43.11; WEBGOAT_ALIAS=webgoat.lab; WEBGOAT_NAME=webgoat-lab
WEBGOAT_IMAGE="$(cat images/webgoat.image.txt)"     # digest-pinned reference
docker rm -f "$WEBGOAT_NAME" >/dev/null 2>&1 || true
docker run -d --name "$WEBGOAT_NAME" --network "$LAB_NET" --ip "$WEBGOAT_IP" \
  --network-alias "$WEBGOAT_ALIAS" --memory 1500m \
  --restart unless-stopped "$WEBGOAT_IMAGE"

echo "lab up: $TARGET_NAME=$TARGET_IP ($TARGET_ALIAS, http/80), dns=$DNS_IP"
echo "lab up: $WEBGOAT_NAME=$WEBGOAT_IP ($WEBGOAT_ALIAS, http/8080 webgoat, http/9090 webwolf) [prepared, scope pending]"

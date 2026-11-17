# Lab-local DNS for the Kryonsec IEEE-research lab.
#
# Serves juice-shop.lab + webgoat.lab and forwards every other name to
# the pinned upstream. It runs with --network host and binds ONLY the
# dns-bridge gateway IP (10.213.44.1), because Docker 28/29 protect
# container IPs on non-internal networks with a raw-table PREROUTING
# drop (-d <ip> ! -i <its-bridge> -j DROP) that would block the
# sandbox's cross-bridge queries to a containerized resolver. A
# host-owned listen address has no container IP, so no guard applies,
# and the sandbox still only reaches it through the egress gate's
# INPUT path (dport 53 to the pinned resolver, default-deny otherwise).
# DNS answers never create connectivity — the L3 boundary does.
#
# --log-queries sends every query to stdout (docker logs), which gives
# the lab a small, honest audit trail of which names the sandbox tried
# to resolve.
FROM alpine:3.22
RUN apk add --no-cache dnsmasq
COPY lab.hosts /etc/lab.hosts
ENTRYPOINT ["dnsmasq", "--no-daemon", "--no-hosts", "--addn-hosts=/etc/lab.hosts", "--no-resolv", "--server=1.1.1.1", "--log-queries"]

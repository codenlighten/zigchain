# ZigChain multi-node testnet

A harness that runs a real multi-node network and asserts it behaves — the thing
a single-process loopback test can't do. Each node runs in its own container with
its **own IP** on an isolated bridge, so this exercises the true multi-host paths:
`getpeername` returns distinct routable IPs, the address-book `routable()` filter,
self-connection detection by nonce, and peer exchange (PEX) across real addresses.
(Two networking bugs — self-dial and 0.0.0.0 poisoning — were originally masked
precisely because the earlier tests ran on loopback.)

## Run it

```sh
deploy/testnet/testnet.sh          # build, run 5 nodes, assert, tear down
KEEP=1 deploy/testnet/testnet.sh   # leave the network up for inspection
```

Only Docker is required (no Compose). The harness:

1. Builds the node image and creates an isolated `172.28.0.0/16` bridge.
2. Starts a **seed** (mining) at `172.28.0.10` and four peers at `.11–.14`. Each
   peer is told **only** about the seed — it must learn the others via PEX.
3. **Convergence** — waits until all five report the same tip at height ≥ 5.
4. **PEX mesh** — asserts each peer reached more than one peer (i.e. it discovered
   others beyond the seed, across distinct container IPs).
5. **Fault recovery** — stops `peer2`, confirms the network keeps advancing
   without it, then restarts it and confirms it re-syncs from scratch and the
   whole network re-converges.

Observability comes from each node's periodic `STATUS height=.. peers=.. tip=..`
log line (`docker logs zct_<name>`); there is no RPC dependency.

## Topology

```
        seed (mines) 172.28.0.10
        /     |     |     \
   peer1    peer2  peer3  peer4      each knows only the seed;
   .11       .12    .13    .14        peers find each other via PEX
```

`docker-compose.yml` describes the same topology declaratively for anyone with
Docker Compose v2 (`docker compose -f deploy/testnet/docker-compose.yml up`); the
`testnet.sh` harness above is the self-contained, version-independent path and is
what CI/verification runs.

## Extending to real, separate machines

The container network is a faithful multi-host stand-in, but for a true
cross-machine testnet run the node on each host (Docker or the AWS one-click
stack in `deploy/aws/`) and point every peer's `ZIGCHAIN_PEER` at the seed's
public `ip:port`. Everything else — discovery, convergence, fault recovery — is
identical; only the addresses change. Open the P2P port between hosts.

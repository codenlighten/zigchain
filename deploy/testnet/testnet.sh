#!/usr/bin/env bash
# Multi-node ZigChain testnet harness (plain docker — no compose dependency).
#
# Brings up a 5-node network on an isolated bridge where each node has its OWN
# container IP, so it exercises the real multi-host paths a loopback test can't:
# getpeername returns distinct routable IPs, the address-book routable() filter,
# self-connection detection by nonce, and peer exchange across real addresses.
#
# Asserts: (1) all nodes converge on one tip, (2) peers discovered each other via
# PEX (not just the seed), (3) the network survives a node failure and the failed
# node re-syncs on return.
#
#   ./testnet.sh          build image, run, assert, tear down
#   KEEP=1 ./testnet.sh   leave the network up for inspection
set -uo pipefail
cd "$(dirname "$0")"

NET=zigchain_testnet
IMG=zigchain:testnet
SEED_IP=172.28.0.10
ALL="seed peer1 peer2 peer3 peer4"
PEERS="peer1 peer2 peer3 peer4"
ip_of() { case "$1" in seed) echo 172.28.0.10;; peer1) echo 172.28.0.11;; peer2) echo 172.28.0.12;; peer3) echo 172.28.0.13;; peer4) echo 172.28.0.14;; esac; }

teardown() {
  [ "${KEEP:-0}" = 1 ] && return
  for n in $ALL; do docker rm -f "zct_$n" >/dev/null 2>&1; done
  docker network rm "$NET" >/dev/null 2>&1
}
trap teardown EXIT

run_node() { # name  [mine]
  local name=$1 mine=${2:-}
  local args=(-d --name "zct_$name" --network "$NET" --ip "$(ip_of "$name")"
              -e ZIGCHAIN_PORT=9000 -e "ZIGCHAIN_NAME=$name")
  if [ "$mine" = mine ]; then args+=(-e ZIGCHAIN_MINE=true); else args+=(-e "ZIGCHAIN_PEER=$SEED_IP:9000"); fi
  docker run "${args[@]}" "$IMG" >/dev/null
}

status() { docker logs "zct_$1" 2>&1 | grep -oE 'STATUS height=[0-9]+ ckpt=[0-9]+ peers=[0-9]+ tip=[0-9a-f]+ stable=[0-9a-f]+' | tail -1; }
field()  { echo "$1" | sed -nE "s/.*[^a-z]$2=([0-9a-f]+).*/\1/p"; }
show()   { for n in $ALL; do printf '  %-6s %s\n' "$n" "$(status "$n")"; done; }
fail()   { echo "❌ $1"; echo "--- state ---"; show; exit 1; }

# Converged when every node reports the same stable checkpoint (same block at the
# same rounded-down height = agreement on the chain, robust to the moving live
# tip) and every node has reached at least min_height.
wait_converge() { # min_height timeout_s
  local minh=$1 deadline=$(( $(date +%s) + $2 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    local ckpts="" stables="" ok=1
    for n in $ALL; do
      local s h c st; s=$(status "$n"); h=$(field "$s" height); c=$(field "$s" ckpt); st=$(field "$s" stable)
      { [ -z "$st" ] || [ "${h:-0}" -lt "$minh" ]; } && { ok=0; break; }
      ckpts="$ckpts $c"; stables="$stables $st"
    done
    if [ "$ok" = 1 ] \
       && [ "$(echo $ckpts | tr ' ' '\n' | sort -u | wc -l)" = 1 ] \
       && [ "$(echo $stables | tr ' ' '\n' | sort -u | wc -l)" = 1 ]; then return 0; fi
    sleep 3
  done
  return 1
}

echo "==> Building image ($IMG)"
docker build -t "$IMG" ../.. >/tmp/tn_build.log 2>&1 || { tail -20 /tmp/tn_build.log; exit 1; }

echo "==> Creating isolated network and starting 5 nodes (distinct IPs)"
teardown
docker network create --driver bridge --subnet 172.28.0.0/16 "$NET" >/dev/null || fail "network create failed"
run_node seed mine
sleep 2
for p in $PEERS; do run_node "$p"; done

echo "==> [1/3] Waiting for all 5 nodes to converge on a stable checkpoint (height >= 60)"
wait_converge 60 200 || fail "nodes did not converge on a common stable checkpoint"
echo "✅ converged (all agree on the stable checkpoint block):"; show

echo "==> [2/3] Asserting PEX meshed the peers across real IPs (each peer sees >1 peer)"
mesh_ok=1
for n in $PEERS; do
  p=$(field "$(status "$n")" peers); echo "  $n peers=${p:-0}"
  [ "${p:-0}" -ge 2 ] || mesh_ok=0
done
[ "$mesh_ok" = 1 ] && echo "✅ peers discovered each other via PEX (beyond just the seed)" \
                   || fail "PEX did not mesh the peers"

echo "==> [3/3] Fault tolerance: stop peer2, confirm the network keeps advancing"
h0=$(field "$(status seed)" height)
docker stop zct_peer2 >/dev/null 2>&1
deadline=$(( $(date +%s) + 90 )); h1=$h0
while [ "$(date +%s)" -lt "$deadline" ]; do
  h1=$(field "$(status seed)" height)
  [ "${h1:-0}" -gt "$((h0 + 3))" ] && break
  sleep 3
done
[ "${h1:-0}" -gt "$((h0 + 3))" ] || fail "network stalled while peer2 was down (stuck at $h0)"
echo "✅ network advanced $h0 -> $h1 without peer2"

echo "==> Restarting peer2; it must re-sync and re-discover peers from scratch"
docker start zct_peer2 >/dev/null 2>&1
wait_converge "$h1" 150 || fail "peer2 did not re-sync/converge after rejoining"
echo "✅ peer2 rejoined and the whole network re-converged:"; show

echo ""
echo "🎉 Testnet passed: convergence, PEX mesh across real IPs, and fault recovery."

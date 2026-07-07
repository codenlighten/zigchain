#!/usr/bin/env bash
# Multi-node ZigChain testnet harness (plain docker — no compose dependency).
#
# Runs a 5-node network on an isolated bridge where each node has its OWN IP:
# TWO mining seeds and three observers. Because two miners race on real IPs with
# real propagation delay, they constantly produce competing (anticone) blocks —
# a genuine BlockDAG fork, not a linear chain. This exercises the core GHOSTDAG
# claim: every node must resolve the same selected chain from the same DAG.
#
# Asserts:
#   1. all nodes converge on the same stable checkpoint,
#   2. the DAG actually forked (count > height) AND was resolved identically
#      everywhere (i.e. #1 holds despite the forks),
#   3. peers discovered each other via PEX across real IPs,
#   4. the network survives a node failure and the node re-syncs on return.
#
#   ./testnet.sh          build image, run, assert, tear down
#   KEEP=1 ./testnet.sh   leave the network up for inspection
set -uo pipefail
cd "$(dirname "$0")"

NET=zigchain_testnet
IMG=zigchain:testnet
SEED_IP=172.28.0.10               # seed1 — the bootstrap root everyone dials
ALL="seed1 seed2 peer1 peer2 peer3"
MINERS="seed1 seed2"
OBSERVERS="peer1 peer2 peer3"
ip_of() { case "$1" in seed1) echo 172.28.0.10;; seed2) echo 172.28.0.11;; peer1) echo 172.28.0.12;; peer2) echo 172.28.0.13;; peer3) echo 172.28.0.14;; esac; }
is_miner() { case " $MINERS " in *" $1 "*) return 0;; *) return 1;; esac; }

teardown() {
  [ "${KEEP:-0}" = 1 ] && return
  for n in $ALL; do docker rm -f "zct_$n" >/dev/null 2>&1; done
  docker network rm "$NET" >/dev/null 2>&1
}
trap teardown EXIT

run_node() { # name
  local name=$1
  local args=(-d --name "zct_$name" --network "$NET" --ip "$(ip_of "$name")"
              -e ZIGCHAIN_PORT=9000 -e "ZIGCHAIN_NAME=$name")
  is_miner "$name" && args+=(-e ZIGCHAIN_MINE=true)
  [ "$name" != seed1 ] && args+=(-e "ZIGCHAIN_PEER=$SEED_IP:9000") # all bootstrap from seed1
  docker run "${args[@]}" "$IMG" >/dev/null
}

status() { docker logs "zct_$1" 2>&1 | grep -oE 'STATUS height=[0-9]+ count=[0-9]+ ckpt=[0-9]+ peers=[0-9]+ tip=[0-9a-f]+ stable=[0-9a-f]+' | tail -1; }
field()  { echo "$1" | sed -nE "s/.*[^a-z]$2=([0-9a-f]+).*/\1/p"; }
show()   { for n in $ALL; do printf '  %-6s %s\n' "$n" "$(status "$n")"; done; }
fail()   { echo "❌ $1"; echo "--- state ---"; show; exit 1; }

# Converged when every node reports the same stable checkpoint (same block at the
# same rounded-down height) and every node has reached at least min_height.
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

echo "==> Creating isolated network and starting 5 nodes (2 miners + 3 observers)"
teardown
docker network create --driver bridge --subnet 172.28.0.0/16 "$NET" >/dev/null || fail "network create failed"
run_node seed1
sleep 2
for n in seed2 $OBSERVERS; do run_node "$n"; done

echo "==> [1/4] Waiting for all 5 nodes to converge on a stable checkpoint (height >= 60)"
wait_converge 60 240 || fail "nodes did not converge on a common stable checkpoint"
echo "✅ converged (all agree on the stable checkpoint block):"; show

echo "==> [2/4] Fork resolution: two miners produce competing blocks — did the DAG fork, and resolve identically?"
fork_ok=1
for n in $ALL; do
  s=$(status "$n"); h=$(field "$s" height); c=$(field "$s" count); forks=$(( ${c:-0} - ${h:-0} ))
  echo "  $n height=$h count=$c off-chain-forks=$forks"
  [ "$forks" -ge 3 ] || fork_ok=0
done
# Convergence (step 1) already proved every node agreed on the stable checkpoint
# DESPITE these forks — i.e. GHOSTDAG selected the same chain from the same DAG.
[ "$fork_ok" = 1 ] && echo "✅ the DAG genuinely forked (count > height) and every node resolved the same selected chain" \
                   || fail "not enough forking to exercise GHOSTDAG competition (need both miners producing siblings)"

echo "==> [3/4] Asserting PEX meshed the peers across real IPs (each observer sees >1 peer)"
mesh_ok=1
for n in $OBSERVERS; do
  p=$(field "$(status "$n")" peers); echo "  $n peers=${p:-0}"
  [ "${p:-0}" -ge 2 ] || mesh_ok=0
done
[ "$mesh_ok" = 1 ] && echo "✅ peers discovered each other via PEX" || fail "PEX did not mesh the peers"

echo "==> [4/4] Fault tolerance: stop peer3, confirm the (two-miner) network keeps advancing"
h0=$(field "$(status seed1)" height)
docker stop zct_peer3 >/dev/null 2>&1
deadline=$(( $(date +%s) + 90 )); h1=$h0
while [ "$(date +%s)" -lt "$deadline" ]; do
  h1=$(field "$(status seed1)" height)
  [ "${h1:-0}" -gt "$((h0 + 3))" ] && break
  sleep 3
done
[ "${h1:-0}" -gt "$((h0 + 3))" ] || fail "network stalled while peer3 was down (stuck at $h0)"
echo "✅ network advanced $h0 -> $h1 without peer3"

echo "==> Restarting peer3; it must re-sync and re-discover peers from scratch"
docker start zct_peer3 >/dev/null 2>&1
wait_converge "$h1" 150 || fail "peer3 did not re-sync/converge after rejoining"
echo "✅ peer3 rejoined and the whole network re-converged:"; show

echo ""
echo "🎉 Testnet passed: two-miner fork resolution, convergence, PEX mesh, and fault recovery."

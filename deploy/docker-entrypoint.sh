#!/bin/sh
# Map ZIGCHAIN_* environment variables to node flags, then exec the node.
#
#   ZIGCHAIN_PORT       TCP port to listen on            (default 9000)
#   ZIGCHAIN_DATADIR    persistent block-log directory   (default /data)
#   ZIGCHAIN_NAME       log label                        (default zigchain)
#   ZIGCHAIN_MINE       "true" to mine blocks            (default false)
#   ZIGCHAIN_PEER       peer(s) to dial, comma-separated (e.g. 1.2.3.4:9000)
#   ZIGCHAIN_BLOCKS     stop after N blocks (0/unset = run forever, the default)
set -eu

ARGS="--datadir ${ZIGCHAIN_DATADIR:-/data} --port ${ZIGCHAIN_PORT:-9000} --name ${ZIGCHAIN_NAME:-zigchain}"

if [ "${ZIGCHAIN_MINE:-false}" = "true" ]; then
    ARGS="$ARGS --mine"
fi

if [ -n "${ZIGCHAIN_PEER:-}" ]; then
    OLD_IFS=$IFS
    IFS=','
    for p in $ZIGCHAIN_PEER; do
        [ -n "$p" ] && ARGS="$ARGS --peer $p"
    done
    IFS=$OLD_IFS
fi

if [ -n "${ZIGCHAIN_BLOCKS:-}" ]; then
    ARGS="$ARGS --blocks ${ZIGCHAIN_BLOCKS}"
fi

echo "starting: zigchain-node $ARGS"
# shellcheck disable=SC2086
exec zigchain-node $ARGS

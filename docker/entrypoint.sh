#!/bin/bash
# run krill-sync with variable interpolation
set -e
DATA="${DATA:-/data}"
RRDP_DIR="${RRDP_DIR:-$DATA/rrdp}"
RSYNC_DIR="${RSYNC_DIR:-$DATA/rsync}"
STATE_DIR="${STATE_DIR:-$DATA/state}"

exec /usr/local/bin/krill-sync \
    -v \
    --rrdp-dir ${RRDP_DIR} \
    --rsync-dir ${RSYNC_DIR} \
    --state-dir ${STATE_DIR} \
    "$@"

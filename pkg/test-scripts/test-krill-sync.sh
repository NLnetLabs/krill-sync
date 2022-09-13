#!/usr/bin/env bash

set -eo pipefail
set -x

case $1 in
  post-install)
    echo -e "\nKRILLC VERSION:"
    krill-sync --version
    ;;

  post-upgrade)
    ;;
esac
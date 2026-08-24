#!/bin/sh
set -eu

profile=${1:-coverage.out}
minimum=${2:-80.0}

if [ ! -f "$profile" ]; then
  echo "coverage profile not found: $profile" >&2
  exit 2
fi

case "$minimum" in
  ''|*[!0-9.]*|*.*.*)
    echo "invalid minimum coverage: $minimum" >&2
    exit 2
    ;;
esac

total=$(
  go tool cover -func="$profile" |
    awk '$1 == "total:" { value=$3; sub(/%$/, "", value); print value }'
)
if [ -z "$total" ]; then
  echo "unable to read total coverage from: $profile" >&2
  exit 2
fi

awk -v actual="$total" -v required="$minimum" 'BEGIN {
  if ((actual + 0) < (required + 0)) {
    printf "Go coverage gate failed: %.1f%% < %.1f%%\n", actual, required > "/dev/stderr"
    exit 1
  }
  printf "Go coverage gate passed: %.1f%% >= %.1f%%\n", actual, required
}'

#!/bin/sh
set -eu

profile=${1:-coverage.out}
minimum=${2:-80.0}

if [ ! -f "$profile" ]; then
  echo "coverage profile not found: $profile" >&2
  exit 2
fi

awk -v required="$minimum" '
BEGIN {
  if (required !~ /^([0-9]+)(\.[0-9]+)?$/ || required + 0 < 0 || required + 0 > 100) {
    printf "invalid minimum coverage: %s\n", required > "/dev/stderr"
    exit 2
  }
}
NR == 1 {
  if ($0 !~ /^mode: (set|count|atomic)$/) {
    printf "invalid coverage profile header: %s\n", $0 > "/dev/stderr"
    exit 2
  }
  next
}
NF != 3 || $2 !~ /^[0-9]+$/ || $3 !~ /^[0-9]+$/ {
  printf "invalid coverage profile line %d\n", NR > "/dev/stderr"
  exit 2
}
{
  # -coverpkg writes the same source block once per tested package. Count a
  # block once and retain its largest execution count so duplicate profiles
  # cannot inflate either the numerator or denominator.
  key = $1 SUBSEP $2
  statements[key] = $2 + 0
  if (!(key in executions) || $3 + 0 > executions[key]) {
    executions[key] = $3 + 0
  }
}
END {
  if (NR < 2) {
    print "coverage profile has no blocks" > "/dev/stderr"
    exit 2
  }
  for (key in statements) {
    total += statements[key]
    if (executions[key] > 0) {
      covered += statements[key]
    }
  }
  if (total <= 0) {
    print "coverage profile has no statements" > "/dev/stderr"
    exit 2
  }
  actual = 100 * covered / total
  if (actual + 1e-12 < required + 0) {
    printf "Go coverage gate failed: %d/%d = %.6f%% < %s%%\n", covered, total, actual, required > "/dev/stderr"
    exit 1
  }
  printf "Go coverage gate passed: %d/%d = %.6f%% >= %s%%\n", covered, total, actual, required
}
' "$profile"

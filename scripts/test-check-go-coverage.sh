#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
tmp_dir=$(mktemp -d)
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM

cat >"$tmp_dir/exact.out" <<'EOF'
mode: atomic
example/a.go:1.1,1.2 8 1
example/a.go:1.1,1.2 8 0
example/a.go:2.1,2.2 2 0
EOF

"$script_dir/check-go-coverage.sh" "$tmp_dir/exact.out" 80 >/dev/null
if "$script_dir/check-go-coverage.sh" "$tmp_dir/exact.out" 80.0001 >/dev/null 2>&1; then
  echo "exact threshold above 80% unexpectedly passed" >&2
  exit 1
fi

cat >"$tmp_dir/rounded.out" <<'EOF'
mode: count
example/b.go:1.1,1.2 8000 1
example/b.go:2.1,2.2 2001 0
EOF

if "$script_dir/check-go-coverage.sh" "$tmp_dir/rounded.out" 80 >/dev/null 2>&1; then
  echo "79.992001% must not pass an 80% gate" >&2
  exit 1
fi

cat >"$tmp_dir/invalid.out" <<'EOF'
not a coverage profile
EOF
if "$script_dir/check-go-coverage.sh" "$tmp_dir/invalid.out" 80 >/dev/null 2>&1; then
  echo "invalid profile unexpectedly passed" >&2
  exit 1
fi
if "$script_dir/check-go-coverage.sh" "$tmp_dir/exact.out" 101 >/dev/null 2>&1; then
  echo "invalid threshold unexpectedly passed" >&2
  exit 1
fi

echo "coverage gate self-test: PASS"

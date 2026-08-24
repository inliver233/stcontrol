#!/bin/sh
set -eu

OUTPUT_DIR="${1:-dist}"
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

for arch in amd64 arm64; do
  artifact="agent-linux-$arch"
  echo "==> Building $artifact"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
    go build -trimpath -ldflags="-s -w" -o "$OUTPUT_DIR/$artifact" ./cmd/agent
  (
    cd "$OUTPUT_DIR"
    sha256sum "$artifact" >"$artifact.sha256"
    sha256sum --check "$artifact.sha256"
  )
done

#!/usr/bin/env bash
# Generate Go gRPC stubs from proto/.
#
# Requires:
#   - protoc          (libprotoc 25+)
#   - protoc-gen-go         (go install google.golang.org/protobuf/cmd/protoc-gen-go@latest)
#   - protoc-gen-go-grpc    (go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/proto"

cd "$ROOT"

for f in $(find proto -name '*.proto'); do
  echo "→ $f"
  protoc \
    -I proto \
    --go_out=proto --go_opt=paths=source_relative \
    --go-grpc_out=proto --go-grpc_opt=paths=source_relative \
    "$f"
done

echo "✓ proto generation complete"

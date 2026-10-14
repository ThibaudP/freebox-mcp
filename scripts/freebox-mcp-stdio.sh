#!/usr/bin/env bash
# Launch the hardened Freebox MCP server over stdio from this checkout's locked venv.
#
# No installs, no network fetches, no uvx: it only execs the binary that
# `uv sync --frozen` placed in .venv. Point your MCP client at the ABSOLUTE path
# of this script. Configuration comes from the environment (see README), e.g.
# FREEBOX_ENABLE_WRITES=true to register the preview-first write tools.
set -euo pipefail
repo="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
bin="$repo/.venv/bin/freebox-mcp"
if [[ ! -x "$bin" ]]; then
  echo "freebox-mcp: $bin not found; run 'uv sync --frozen' in $repo first." >&2
  exit 1
fi
exec "$bin" "$@"

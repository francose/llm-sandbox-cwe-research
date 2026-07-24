#!/usr/bin/env bash
# env_inherit.sh -- inherited-context risk in ~5 lines.
# A local CLI agent starts with the developer's exported environment. Any child
# process it spawns (a subagent, a shelled-out tool, an MCP server) inherits that
# environment by default -- the secret is never passed on argv, yet the child reads it.
set -euo pipefail
export FAKE_API_KEY="sk-demo-DEADBEEF-not-a-real-secret"          # (1) parent exports a "secret"
echo "parent PID $$ exported FAKE_API_KEY (value not shown on any child's argv)"
python3 -c 'import os; k="FAKE_API_KEY"; print("child  PID", os.getpid(), "inherited", k, "=", os.environ[k])'  # (2) separate process
env | grep -c '^FAKE_API_KEY=' >/dev/null && echo "verdict: child (distinct PID) read the parent secret from its inherited environment"

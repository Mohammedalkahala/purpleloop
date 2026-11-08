#!/usr/bin/env bash
# Lint the master rules, push to Wazuh, validate + restart (auto-rollback on Wazuh).
set -euo pipefail
PL="$HOME/purpleloop"
MASTER="$PL/rules/local_rules.xml"
WH="mohammed@10.10.30.10"
KEY="$HOME/.ssh/purpleloop_runner"

cd "$PL"
echo "== Linting master rules =="
.venv/bin/purpleloop lint

echo "== Copying master to Wazuh =="
scp -i "$KEY" -o StrictHostKeyChecking=accept-new "$MASTER" "$WH:/tmp/local_rules.xml"

echo "== Applying on Wazuh (validate + restart) =="
ssh -i "$KEY" "$WH" "sudo /usr/local/sbin/apply_rules.sh"

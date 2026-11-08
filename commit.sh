#!/usr/bin/env bash
# Approve a deployed detection: copy it to detections/<CVE>/ and commit + push with the master rules.
set -euo pipefail
CVE="${1:?usage: commit.sh CVE-YYYY-NNNN}"
[[ "$CVE" =~ ^CVE-[0-9]{4}-[0-9]{4,7}$ ]] || { echo "ERROR: bad CVE ID"; exit 2; }
PL="$HOME/purpleloop"; D="$PL/drafts/$CVE"; OUTD="$PL/detections/$CVE"
grep -q '^deployed' "$D/status" 2>/dev/null || { echo "ERROR: $CVE is not deployed"; exit 2; }
mkdir -p "$OUTD"
cp "$D/final.xml" "$OUTD/wazuh.xml"
[ -s "$D/sigma.yml" ] && cp "$D/sigma.yml" "$OUTD/sigma.yml"
[ -s "$D/meta.json" ] && cp "$D/meta.json" "$OUTD/meta.json"
[ -s "$D/draft.md" ] && cp "$D/draft.md" "$OUTD/agent-draft.md"
cd "$PL"
for p in "drafts/" "rules/backup/" "*.pre-revert"; do grep -qxF "$p" .gitignore 2>/dev/null || echo "$p" >> .gitignore; done
git add .gitignore rules/local_rules.xml "detections/$CVE"
git commit -q -m "Add detection for $CVE (deployed, tested and approved)"
git push -q origin HEAD
echo "approved $(date -Is)" >> "$D/status"
echo "COMMIT OK: $CVE pushed as $(git rev-parse --short HEAD)"

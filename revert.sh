#!/usr/bin/env bash
# Remove a finalized detection (only its own block, so later rules stay) and redeploy.
set -euo pipefail
CVE="${1:?usage: revert.sh CVE-YYYY-NNNN}"
[[ "$CVE" =~ ^CVE-[0-9]{4}-[0-9]{4,7}$ ]] || { echo "ERROR: bad CVE ID"; exit 2; }
PL="$HOME/purpleloop"; MASTER="$PL/rules/local_rules.xml"; D="$PL/drafts/$CVE"
grep -q '^deployed' "$D/status" 2>/dev/null || { echo "ERROR: $CVE is not deployed"; exit 2; }
TS=$(awk '/^deployed/{print $2}' "$D/status")
cp "$MASTER" "$MASTER.pre-revert"
python3 - "$MASTER" "$D/final.xml" "<!-- $CVE: added $TS by finalize.sh -->" <<'PY'
import sys
master, final, mark = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(master).read(); block = "\n" + mark + "\n" + open(final).read()
if block not in s: sys.exit("ERROR: could not find this CVE's block in the master rules; nothing changed")
open(master, "w").write(s.replace(block, "", 1))
PY
if OUT=$("$PL/deploy.sh" 2>&1) && grep -q "DEPLOY OK" <<<"$OUT"; then
  echo "$OUT"; echo "rejected $(date -Is) (was deployed $TS)" > "$D/status"; rm -f "$MASTER.pre-revert"
  echo "REVERT OK: $CVE removed and rules redeployed"
else
  echo "$OUT"; mv "$MASTER.pre-revert" "$MASTER"; echo "REVERT FAILED: master left unchanged"; exit 4
fi

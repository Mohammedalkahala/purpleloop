#!/usr/bin/env bash
# Finalize a reviewed draft: check it, append it to the master rules, deploy. Restores master if the deploy fails.
set -euo pipefail
CVE="${1:?usage: finalize.sh CVE-YYYY-NNNN}"
[[ "$CVE" =~ ^CVE-[0-9]{4}-[0-9]{4,7}$ ]] || { echo "ERROR: '$CVE' is not a CVE ID"; exit 2; }
PL="$HOME/purpleloop"; MASTER="$PL/rules/local_rules.xml"; D="$PL/drafts/$CVE"; BK="$PL/rules/backup"
[ -s "$D/wazuh.xml" ] || { echo "ERROR: $D/wazuh.xml is missing or empty"; exit 2; }
grep -q 'NO RULE' "$D/wazuh.xml" && { echo "ERROR: the draft says NO RULE"; exit 2; }
if [ -f "$D/status" ] && grep -q '^deployed' "$D/status"; then echo "ERROR: $CVE is already deployed (see $D/status)"; exit 2; fi

F="$D/final.xml"
sed -e 's/purpleloop,draft,/purpleloop,cve,/' "$D/wazuh.xml" > "$F"
( echo "<root>"; cat "$F"; echo "</root>" ) | xmllint --noout - || { echo "ERROR: final XML is not well-formed"; exit 3; }
IDS=$(grep -o 'rule id="[0-9]*"' "$F" | grep -o '[0-9]*' || true)
[ -n "$IDS" ] || { echo "ERROR: no rule IDs found"; exit 3; }
for id in $IDS; do
  { [ "$id" -ge 100500 ] && [ "$id" -le 100999 ]; } || { echo "ERROR: rule id $id is outside 100500-100999"; exit 3; }
  grep -q "rule id=\"$id\"" "$MASTER" && { echo "ERROR: rule id $id is already in the master rules"; exit 3; }
done

mkdir -p "$BK"; TS=$(date +%Y%m%d-%H%M%S); cp "$MASTER" "$BK/local_rules.xml.$TS"
MARK="<!-- $CVE: added $TS by finalize.sh -->"
printf '\n%s\n' "$MARK" >> "$MASTER"; cat "$F" >> "$MASTER"

if OUT=$("$PL/deploy.sh" 2>&1) && grep -q "DEPLOY OK" <<<"$OUT"; then
  echo "$OUT"
  printf 'deployed %s\nids %s\n' "$TS" "$(echo $IDS)" > "$D/status"
  echo "FINALIZE OK: $CVE deployed as rule(s) $(echo $IDS) (backup $TS)"
else
  echo "$OUT"
  cp "$BK/local_rules.xml.$TS" "$MASTER"
  echo "FINALIZE FAILED: master rules restored from backup $TS"; exit 4
fi

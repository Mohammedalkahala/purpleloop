# PurpleLoop

**Grade Wazuh detection rules with lab evidence, not opinions, and turn every graded rule into
verified training data.**

You run a test (for example an Atomic Red Team test) on a lab machine. PurpleLoop then asks
Wazuh four questions for each rule you expected to fire:

| Question | How it's answered |
|---|---|
| Did the rule alert inside the test window? | Wazuh **alerts** index (ground truth) |
| If not, did the telemetry even arrive? | Wazuh **archives** index (every event, not just alerts) |
| If it arrived, would the rule's conditions have matched it? | Local **replay** of the rule's `pcre2` fields |
| How noisy is the rule on normal activity? | Replay over the days **before** the test |

That gives each rule a diagnosis a human can act on:

| Diagnosis | Meaning | Usual fix |
|---|---|---|
| `DETECTED` | Alert fired in the window | Check the false-positive estimate |
| `SHADOWED` | Events match the rule, but no alert | A sibling rule takes the event first; add it to `if_sid`, or restart the manager |
| `MISMATCH` | Events arrived but don't match | Compare the regex with the sample values in the report |
| `NO_TELEMETRY` | No candidate events | The test didn't run, logging is off, or the channel isn't shipped |

`SHADOWED` comes from a real bug found while building this lab: built-in level-0 rules
(92300/92304/92307) silently took Sysmon Event 13, so a custom Run-key rule never fired.

## Why the human runs the test
PurpleLoop never executes attacks. You choose and run the test; PurpleLoop measures the result.
That keeps the loop safe to point at real infrastructure, and it is how detection teams work.

## Training data (the long game)
Every grade is appended to `data/graded.jsonl` with the rule XML, verdict, false-positive rate,
telemetry samples, and **provenance** (who wrote the rule). `purpleloop dataset export` turns the
rules that passed into chat-format examples for fine-tuning an open model, and **excludes
provenance you list** (default: anything containing `claude`). Check the terms of any hosted
model before training on its outputs.

## Install
```bash
git clone https://github.com/Mohammedalkahala/purpleloop && cd purpleloop
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
cp config.example.yaml config.yaml      # point it at your indexer
cp .env.example .env && chmod 600 .env  # indexer password
```

### Create a read-only indexer user (run on the Wazuh server)
PurpleLoop only needs to **read** alerts and archives:
```bash
ADMIN='your-admin-password'
curl -sk -u admin:"$ADMIN" -X PUT https://localhost:9200/_plugins/_security/api/roles/purpleloop_read \
  -H 'Content-Type: application/json' -d '{
  "cluster_permissions": ["cluster_composite_ops_ro", "cluster:monitor/main"],
  "index_permissions": [{"index_patterns": ["wazuh-alerts-*","wazuh-archives-*"], "allowed_actions": ["read"]}]}'
curl -sk -u admin:"$ADMIN" -X PUT https://localhost:9200/_plugins/_security/api/internalusers/purpleloop \
  -H 'Content-Type: application/json' -d '{"password": "A-Strong-Passw0rd.", "backend_roles": []}'
curl -sk -u admin:"$ADMIN" -X PUT https://localhost:9200/_plugins/_security/api/rolesmapping/purpleloop_read \
  -H 'Content-Type: application/json' -d '{"users": ["purpleloop"]}'
```
Archives must be enabled (`<logall_json>yes</logall_json>` in `ossec.conf`, and `archives:
enabled: true` in `/etc/filebeat/filebeat.yml`).

## Use
```bash
purpleloop check                                  # indexer reachable? docs in last 24h?
purpleloop lint                                   # static checks (+ optional manager check)
# ...run your test on the lab machine, wait ~2 minutes for ingestion...
purpleloop grade cases/T1547.001-runkey.yaml --since 15m
purpleloop dataset stats
purpleloop dataset export --out train.jsonl
```
Exit code is `0` only when every expected rule passes, so it drops straight into CI.

## A case file
```yaml
id: T1547.001-runkey
title: Registry Run key persistence
technique: T1547.001
agent: office01
test: {performed_by: human, how: "Invoke-AtomicTest T1547.001 -TestNumbers 1"}
expected_rules: [100200, 100201]
rules_meta:
  100200: {author: "...", provenance: [human-validated], license: Apache-2.0}
```

## Honest limits
- Replay approximates parent rules with a candidate query (Sysmon event ID by default) and only
  understands `pcre2` fields. Alerts are ground truth; replay explains them.
- The false-positive estimate is only as good as your baseline. Reports state the hours covered
  and mark less than 24h as low confidence.

## Roadmap
- [x] Grader: alerts + archive replay + FP baseline + reports + dataset
- [x] Method: [docs/WRITING_A_RULE.md](docs/WRITING_A_RULE.md)
- [ ] Rule-writing agent (local model triage, hosted model drafting, lint + retry)
- [ ] Discord approve/reject with grader evidence → Git commit → deploy to Wazuh
- [ ] Lane 2: Suricata rules graded the same way
- [ ] Fine-tune a small open model on lab-verified rules; benchmark it with the grader

License: Apache-2.0

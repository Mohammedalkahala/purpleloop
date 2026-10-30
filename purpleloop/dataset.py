"""Every graded rule becomes a record; validated ones become training examples.

Provenance is mandatory. It records who wrote each rule (human, an open model, or a hosted
model) so the training export can exclude sources you may not train on. Read the terms of any
hosted model you used before training a model on its outputs.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

SYSTEM_PROMPT = ("You are a detection engineer. Write a single Wazuh custom rule in XML that detects "
                 "the described behavior using the telemetry fields shown. Use pcre2 field matches, "
                 "the correct parent rule, a clear description and a MITRE mapping.")


def append_records(path: str | Path, report: dict, rules_xml: dict[str, str], case: dict) -> int:
    meta = case.get("rules_meta") or {}
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with p.open("a", encoding="utf-8") as fh:
        for r in report["rules"]:
            m = meta.get(str(r["rule_id"]), {}) or {}
            rec = {
                "record_version": 1,
                "graded_at": report["graded_at"],
                "purpleloop_version": report["purpleloop_version"],
                "case_id": report["case"]["id"],
                "technique": report["case"]["technique"],
                "title": report["case"]["title"],
                "test": report["case"]["test"],
                "rule_id": r["rule_id"],
                "rule_xml": rules_xml.get(r["rule_id"], ""),
                "verdict": r["verdict"],
                "diagnosis": r["diagnosis"],
                "alerts_in_window": r["alerts_in_window"],
                "fp_per_day": (r.get("baseline") or {}).get("matches_per_day"),
                "fp_confidence": (r.get("baseline") or {}).get("confidence"),
                "telemetry_samples": r.get("sample_values", {}),
                "author": m.get("author", "unknown"),
                "provenance": m.get("provenance", ["unknown"]),
                "license": m.get("license", "unspecified"),
            }
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            n += 1
    return n


def load(path: str | Path) -> list[dict]:
    p = Path(path)
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


def export_training(records: list[dict], exclude_provenance: list[str],
                    include_noisy: bool = False) -> tuple[list[dict], dict]:
    """Latest verdict per (case, rule) wins. Returns (chat-format examples, stats)."""
    latest: dict[tuple[str, str], dict] = {}
    for r in records:
        latest[(r["case_id"], r["rule_id"])] = r
    ok = {"PASS", "NOISY"} if include_noisy else {"PASS"}
    stats = {"records": len(records), "unique": len(latest), "kept": 0,
             "skipped_verdict": 0, "skipped_provenance": 0, "skipped_unknown_provenance": 0}
    out: list[dict] = []
    bad = {x.lower() for x in exclude_provenance}
    for r in latest.values():
        prov = [str(x).lower() for x in r.get("provenance", [])]
        if r["verdict"] not in ok:
            stats["skipped_verdict"] += 1
            continue
        if not r.get("rule_xml"):
            stats["skipped_no_rule_text"] = stats.get("skipped_no_rule_text", 0) + 1
            continue
        if not prov or "unknown" in prov:
            stats["skipped_unknown_provenance"] += 1
            continue
        if any(any(b in p for b in bad) for p in prov):
            stats["skipped_provenance"] += 1
            continue
        samples = "\n".join(f"- {k}: {v[0]}" for k, v in (r.get("telemetry_samples") or {}).items() if v)
        user = (f"Technique: {r['technique']} - {r['title']}\n"
                f"Test that must be detected: {r['test'].get('how', '') if isinstance(r['test'], dict) else r['test']}\n"
                f"Example telemetry:\n{samples or '- (none recorded)'}")
        out.append({
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user},
                {"role": "assistant", "content": r["rule_xml"]},
            ],
            "meta": {k: r[k] for k in ("case_id", "rule_id", "verdict", "fp_per_day", "author",
                                        "provenance", "license", "graded_at")},
        })
        stats["kept"] += 1
    stats["exported_at"] = datetime.now(timezone.utc).isoformat()
    return out, stats

"""Grade detection rules with evidence from Wazuh.

You run the test (e.g. an Atomic Red Team test) yourself. Then the grader answers, per rule:

  * DETECTED      - the rule raised an alert on the target inside the test window
  * SHADOWED      - telemetry arrived AND the rule's conditions match it, yet no alert:
                    another rule in the tree took the event first, the rule isn't loaded,
                    or the manager wasn't restarted (the "silent 92300" lesson)
  * MISMATCH      - telemetry arrived but the rule's conditions don't match it
  * NO_TELEMETRY  - no candidate events at all: the test didn't produce what we expected,
                    logging is off, or the agent isn't shipping that channel

...and how noisy it would be: replaying the rule over normal activity before the test.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

from .rules import Rule, get_path, lint, replay_match

VERSION = "0.1.0"


@dataclass
class Baseline:
    days_requested: int
    covered_hours: float = 0.0
    candidates: int = 0
    replay_matches: int = 0
    alerts_outside_window: int = 0
    matches_per_day: float = 0.0
    confidence: str = "none"      # none | low | ok
    truncated: bool = False


@dataclass
class RuleResult:
    rule_id: str
    description: str = ""
    level: int = -1
    mitre: list[str] = field(default_factory=list)
    lint: list[str] = field(default_factory=list)
    alerts_in_window: int = 0
    first_alert: str = ""
    sample_alert: str = ""
    candidates_in_window: int = 0
    replay_matches_in_window: int = 0
    replayable: bool = False
    candidate_query: str = ""
    diagnosis: str = ""
    verdict: str = ""
    reason: str = ""
    sample_values: dict[str, list[str]] = field(default_factory=dict)
    baseline: Baseline | None = None


def _q(v: str) -> str:
    return '"' + str(v).replace('"', '\\"') + '"'


def candidate_query(rule: Rule, agent: str, override: str | None) -> str:
    if override:
        return f"agent.name:{_q(agent)} AND ({override})"
    ids = sorted(rule.default_event_ids())
    q = f"agent.name:{_q(agent)}"
    if ids:
        q += " AND data.win.system.eventID:(" + " OR ".join(ids) + ")"
    return q


def _samples(rule: Rule, docs: list[dict], n: int = 3) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for c in rule.fields:
        vals: list[str] = []
        for d in docs:
            v = get_path(d, c.doc_path)
            if v is not None:
                s = str(v)[:200]
                if s not in vals:
                    vals.append(s)
            if len(vals) >= n:
                break
        out[c.name] = vals
    return out


def grade_rule(ix, rule: Rule, case: dict, cfg: dict, start: datetime, end: datetime) -> RuleResult:
    g = cfg.get("grading", {})
    alerts_idx = cfg["indexer"].get("alerts_index", "wazuh-alerts-*")
    archives_idx = cfg["indexer"].get("archives_index", "wazuh-archives-*")
    agent = case["agent"]
    per_rule = (case.get("rule_overrides") or {}).get(rule.id, {}) or {}

    res = RuleResult(rule_id=rule.id, description=rule.description, level=rule.level,
                     mitre=rule.mitre, replayable=rule.replayable)
    res.lint = lint({rule.id: rule})[rule.id]

    # ---- 1. True positive: did it alert in the window? -------------------------------
    alert_q = f"rule.id:{_q(rule.id)} AND agent.name:{_q(agent)}"
    alerts = ix.search(alerts_idx, alert_q, start, end, limit=50,
                       source=["timestamp", "rule.description"])
    res.alerts_in_window = len(alerts)
    if alerts:
        res.first_alert = alerts[0].get("timestamp", "")
        res.sample_alert = str(get_path(alerts[0], "rule.description") or "")[:300]

    # ---- 2. Telemetry + replay inside the window (diagnostics) -----------------------
    res.candidate_query = candidate_query(rule, agent, per_rule.get("candidate_query"))
    max_ev = int(g.get("max_window_events", 5000))
    window_docs = ix.search(archives_idx, res.candidate_query, start, end, limit=max_ev)
    res.candidates_in_window = len(window_docs)
    res.replay_matches_in_window = sum(1 for d in window_docs if replay_match(rule, d))
    res.sample_values = _samples(rule, window_docs)

    if res.alerts_in_window:
        res.diagnosis = "DETECTED"
    elif not res.candidates_in_window:
        res.diagnosis = "NO_TELEMETRY"
    elif not rule.replayable:
        res.diagnosis = "MISS_UNREPLAYABLE"
    elif res.replay_matches_in_window:
        res.diagnosis = "SHADOWED"
    else:
        res.diagnosis = "MISMATCH"

    # ---- 3. False positives: replay over normal activity before the test -------------
    days = int(g.get("baseline_days", 7))
    b = Baseline(days_requested=days)
    b_start = start - timedelta(days=days)
    max_base = int(g.get("max_baseline_events", 20000))
    first = ix.search(archives_idx, f"agent.name:{_q(agent)}", b_start, start, limit=1,
                      source=["timestamp"])
    if first:
        try:
            ts = datetime.fromisoformat(first[0]["timestamp"].replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            b.covered_hours = round(max((start - ts).total_seconds(), 0) / 3600, 1)
        except (KeyError, ValueError):
            b.covered_hours = 0.0
    base_docs = ix.search(archives_idx, res.candidate_query, b_start, start, limit=max_base)
    b.candidates = len(base_docs)
    b.truncated = len(base_docs) >= max_base
    b.replay_matches = sum(1 for d in base_docs if replay_match(rule, d)) if rule.replayable else 0
    b.alerts_outside_window = ix.count(alerts_idx, alert_q, b_start, start)
    days_covered = max(b.covered_hours / 24, 1 / 24)
    b.matches_per_day = round(max(b.replay_matches, b.alerts_outside_window) / days_covered, 2)
    min_hours = float(g.get("min_baseline_hours", 24))
    b.confidence = "none" if b.covered_hours == 0 else ("low" if b.covered_hours < min_hours else "ok")
    res.baseline = b

    # ---- 4. Verdict ------------------------------------------------------------------
    fp_max = float(g.get("fp_max_per_day", 5))
    if any(p.startswith("ERROR") for p in res.lint):
        res.verdict, res.reason = "FAIL", "lint errors"
    elif res.diagnosis != "DETECTED":
        res.verdict, res.reason = "FAIL", {
            "NO_TELEMETRY": "no candidate events in the window - check the test ran and the channel is shipped",
            "SHADOWED": "events match the rule's conditions but no alert - check parents (if_sid), "
                        "sibling rules taking the event first, and that the manager was restarted",
            "MISMATCH": "events arrived but the rule's conditions don't match them - compare with sample values",
            "MISS_UNREPLAYABLE": "no alert; rule uses non-pcre2 fields so replay can't explain why",
        }[res.diagnosis]
    elif b.matches_per_day > fp_max:
        res.verdict = "NOISY"
        res.reason = f"~{b.matches_per_day}/day on normal activity (limit {fp_max:g})"
    else:
        res.verdict = "PASS"
        res.reason = "fired on the test" + (
            "" if b.confidence == "ok" else f"; false-positive estimate has {b.confidence} confidence "
            f"({b.covered_hours}h of baseline)")
    return res


def grade_case(ix, rules: dict[str, Rule], case: dict, cfg: dict,
               start: datetime, end: datetime) -> dict:
    results: list[RuleResult] = []
    for rid in [str(r) for r in case["expected_rules"]]:
        if rid not in rules:
            results.append(RuleResult(rule_id=rid, verdict="FAIL", diagnosis="NOT_FOUND",
                                      reason=f"rule {rid} not in rules file"))
            continue
        results.append(grade_rule(ix, rules[rid], case, cfg, start, end))
    verdicts = {r.verdict for r in results}
    overall = "FAIL" if "FAIL" in verdicts else ("NOISY" if "NOISY" in verdicts else "PASS")
    return {
        "purpleloop_version": VERSION,
        "case": {k: case.get(k) for k in ("id", "title", "technique", "agent", "test")},
        "window": {"start": start.isoformat(), "end": end.isoformat()},
        "graded_at": datetime.now(timezone.utc).isoformat(),
        "overall": overall,
        "rules": [asdict(r) for r in results],
    }

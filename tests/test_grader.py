"""Offline tests: a fake indexer replays realistic office01 events (values copied from real alerts)."""

import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from purpleloop import dataset  # noqa: E402
from purpleloop.grader import grade_case  # noqa: E402
from purpleloop.rules import lint, parse_rules, replay_match  # noqa: E402

NOW = datetime(2026, 10, 27, 2, 0, tzinfo=timezone.utc)
START, END = NOW - timedelta(minutes=15), NOW
SID = r"HKU\\S-1-5-21-2170846766-4221143325-3036473525-1003"


def ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"


def ev13(when, target, image=r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"):
    return {"timestamp": ts(when), "agent": {"name": "office01"},
            "data": {"win": {"system": {"eventID": "13"},
                             "eventdata": {"targetObject": target, "image": image}}}}


def ev1(when, image, cmd):
    return {"timestamp": ts(when), "agent": {"name": "office01"},
            "data": {"win": {"system": {"eventID": "1"},
                             "eventdata": {"image": image, "commandLine": cmd}}}}


def alert(when, rid, desc="x"):
    return {"timestamp": ts(when), "agent": {"name": "office01"}, "rule": {"id": rid, "description": desc}}


RUN_ATOMIC = SID + r"\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Atomic Red Team"
RUN_ONEDRIVE = SID + r"\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive"
BENIGN_KEY = r"HKLM\\System\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\x"
REG_EXE = r"C:\\Windows\\System32\\reg.exe"
CMD_EXE = r"C:\\Windows\\System32\\cmd.exe"
REG_CMD = r'REG  ADD \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /V \"Atomic Red Team\" /t REG_SZ /F'


class FakeIndexer:
    """Understands only the query shapes the grader emits."""

    def __init__(self, alerts=(), archives=()):
        self.docs = {"wazuh-alerts-*": list(alerts), "wazuh-archives-*": list(archives)}

    @staticmethod
    def _match(doc, qs):
        for field, val in re.findall(r'([\w.]+):"([^"]*)"', qs):
            cur = doc
            for p in field.split("."):
                cur = cur.get(p, {}) if isinstance(cur, dict) else {}
            if str(cur) != val:
                return False
        m = re.search(r"data\.win\.system\.eventID:\(([^)]*)\)", qs)
        if m:
            ids = {x.strip() for x in m.group(1).split("OR")}
            if doc.get("data", {}).get("win", {}).get("system", {}).get("eventID") not in ids:
                return False
        return True

    def search(self, index, qs, start, end, limit=20000, source=None):
        out = []
        for d in sorted(self.docs[index], key=lambda d: d["timestamp"]):
            t = datetime.fromisoformat(d["timestamp"])
            if start <= t < end and self._match(d, qs):
                out.append(d)
        return out[:limit]

    def count(self, index, qs, start, end):
        return len(self.search(index, qs, start, end))


RULES = parse_rules(ROOT / "rules" / "local_rules.xml")
CFG = {"indexer": {}, "grading": {"baseline_days": 7, "min_baseline_hours": 24, "fp_max_per_day": 5}}
CASE = {"id": "T1547.001-runkey", "title": "Run key", "technique": "T1547.001", "agent": "office01",
        "expected_rules": ["100200", "100201"], "test": {"how": "atomic"},
        "rules_meta": {"100200": {"author": "a", "provenance": ["claude-assisted", "human-validated"]},
                       "100201": {"author": "b", "provenance": ["human"]}}}


def baseline(days=2, onedrive_per_day=1, benign_per_hour=4):
    docs = []
    t0 = START - timedelta(days=days)
    for h in range(days * 24):
        for i in range(benign_per_hour):
            docs.append(ev13(t0 + timedelta(hours=h, minutes=i), BENIGN_KEY))
    for d in range(days):
        for i in range(onedrive_per_day):
            docs.append(ev13(t0 + timedelta(days=d, hours=9, minutes=i),
                             RUN_ONEDRIVE, r"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe"))
    return docs


def in_window():
    w = START + timedelta(minutes=5)
    return [ev13(w, RUN_ATOMIC, REG_EXE), ev1(w, REG_EXE, REG_CMD), ev1(w, CMD_EXE, '"cmd.exe" /c ' + REG_CMD)]


def by_id(rep):
    return {r["rule_id"]: r for r in rep["rules"]}


def test_replay_matches_real_values_and_excludes_cmd_parent():
    assert replay_match(RULES["100200"], ev13(NOW, RUN_ATOMIC))
    assert not replay_match(RULES["100200"], ev13(NOW, BENIGN_KEY))
    assert replay_match(RULES["100201"], ev1(NOW, REG_EXE, REG_CMD))
    # The duplicate-alert fix: cmd.exe carrying the same command line must NOT match.
    assert not replay_match(RULES["100201"], ev1(NOW, CMD_EXE, '"cmd.exe" /c ' + REG_CMD))


def test_detected_and_pass():
    w = START + timedelta(minutes=5, seconds=40)
    ix = FakeIndexer(alerts=[alert(w, "100200"), alert(w, "100201")], archives=baseline() + in_window())
    rep = grade_case(ix, RULES, CASE, CFG, START, END)
    r = by_id(rep)
    assert rep["overall"] == "PASS", rep
    assert r["100200"]["diagnosis"] == "DETECTED"
    assert r["100200"]["baseline"]["replay_matches"] == 2      # one OneDrive write per day
    assert r["100200"]["baseline"]["confidence"] == "ok"
    assert r["100201"]["replay_matches_in_window"] == 1        # reg.exe only, not cmd.exe


def test_shadowed_when_events_match_but_no_alert():
    rep = grade_case(FakeIndexer(archives=baseline() + in_window()), RULES, CASE, CFG, START, END)
    r = by_id(rep)
    assert r["100200"]["diagnosis"] == "SHADOWED"
    assert r["100200"]["verdict"] == "FAIL"


def test_mismatch_when_events_dont_match():
    w = START + timedelta(minutes=5)
    rep = grade_case(FakeIndexer(archives=[ev13(w, BENIGN_KEY)]), RULES, CASE, CFG, START, END)
    r = by_id(rep)["100200"]
    assert r["diagnosis"] == "MISMATCH"
    assert r["sample_values"]["win.eventdata.targetObject"][0].endswith(r"UserSettings\\x")


def test_no_telemetry():
    rep = grade_case(FakeIndexer(), RULES, CASE, CFG, START, END)
    assert {r["diagnosis"] for r in rep["rules"]} == {"NO_TELEMETRY"}
    assert by_id(rep)["100200"]["baseline"]["confidence"] == "none"


def test_noisy_when_baseline_is_full_of_matches():
    w = START + timedelta(minutes=5, seconds=40)
    ix = FakeIndexer(alerts=[alert(w, "100200"), alert(w, "100201")],
                     archives=baseline(onedrive_per_day=20) + in_window())
    r = by_id(grade_case(ix, RULES, CASE, CFG, START, END))["100200"]
    assert r["verdict"] == "NOISY"
    assert r["baseline"]["matches_per_day"] >= 19


def test_low_confidence_baseline_still_passes_but_says_so():
    w = START + timedelta(minutes=5, seconds=40)
    short = [d for d in baseline(days=1) if datetime.fromisoformat(d["timestamp"]) > START - timedelta(hours=3)]
    ix = FakeIndexer(alerts=[alert(w, "100200"), alert(w, "100201")], archives=short + in_window())
    r = by_id(grade_case(ix, RULES, CASE, CFG, START, END))["100200"]
    assert r["verdict"] == "PASS" and r["baseline"]["confidence"] == "low"
    assert "low confidence" in r["reason"]


def test_lint_catches_bad_rules(tmp_path):
    p = tmp_path / "bad.xml"
    p.write_text('<group name="x,"><rule id="100300" level="10">'
                 '<field name="win.eventdata.image" type="pcre2">(?i)(unclosed</field>'
                 '<mitre><id>1547</id></mitre></rule>'
                 '<rule id="100300" level="99"><if_sid>61603</if_sid><description>d</description></rule></group>')
    probs = lint(parse_rules(p))["100300"]
    text = " ".join(probs)
    assert "ERROR" in text and "duplicate" in text and "level" in text


def test_dataset_export_respects_provenance(tmp_path):
    w = START + timedelta(minutes=5, seconds=40)
    ix = FakeIndexer(alerts=[alert(w, "100200"), alert(w, "100201")], archives=baseline() + in_window())
    rep = grade_case(ix, RULES, CASE, CFG, START, END)
    path = tmp_path / "graded.jsonl"
    assert dataset.append_records(path, rep, {k: v.xml for k, v in RULES.items()}, CASE) == 2
    ex, stats = dataset.export_training(dataset.load(path), exclude_provenance=["claude"])
    assert stats["kept"] == 1 and stats["skipped_provenance"] == 1
    assert ex[0]["meta"]["rule_id"] == "100201"
    assert ex[0]["messages"][2]["content"].startswith('<rule id="100201"')
    assert "reg.exe" in ex[0]["messages"][1]["content"]
    ex_all, _ = dataset.export_training(dataset.load(path), exclude_provenance=[])
    assert len(ex_all) == 2

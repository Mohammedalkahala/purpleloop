"""Parse, lint and locally *replay* Wazuh custom rules.

Replay is an approximation on purpose: it evaluates a rule's <field> conditions (pcre2)
against stored events, so we can ask "would this rule have matched?" without touching the
manager. Parent-rule logic (if_sid) is approximated by a candidate query (e.g. Sysmon event ID).
Every result that relies on replay is labeled as such in reports.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

CUSTOM_ID_MIN, CUSTOM_ID_MAX = 100000, 120000
MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# Parent rules whose Sysmon event ID we have verified on a real Wazuh 4.14 install.
# Used to build a default candidate query; a case file can always override it.
KNOWN_PARENT_EVENT_IDS = {
    "61603": "1",    # Sysmon - Event 1: process creation
    "61615": "13",   # Sysmon - Event 13: registry value set
    "92041": "1",    # child of 61603 (Base64-like registry value in command line)
    "92300": "13",   # group sysmon_event_13 children (0860-sysmon_id_13.xml)
    "92304": "13",
    "92307": "13",
}


@dataclass
class FieldCond:
    name: str            # Wazuh decoded field, e.g. win.eventdata.targetObject
    pattern: str
    kind: str            # pcre2 | osregex | osmatch | ...
    negate: bool = False
    compiled: re.Pattern | None = None
    error: str = ""

    @property
    def doc_path(self) -> str:
        # Wazuh stores decoded fields under "data." in indexed documents.
        return "data." + self.name


@dataclass
class Rule:
    id: str
    level: int
    description: str
    if_sid: list[str] = field(default_factory=list)
    if_group: list[str] = field(default_factory=list)
    fields: list[FieldCond] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    xml: str = ""

    @property
    def replayable(self) -> bool:
        return bool(self.fields) and all(f.compiled is not None for f in self.fields)

    def default_event_ids(self) -> set[str]:
        return {KNOWN_PARENT_EVENT_IDS[s] for s in self.if_sid if s in KNOWN_PARENT_EVENT_IDS}


def _compile(cond: FieldCond) -> None:
    if cond.kind != "pcre2":
        cond.error = f"type '{cond.kind}' not replayable (only pcre2 is)"
        return
    pat, flags = cond.pattern, 0
    # Python's re understands a leading (?i) and nearly all syntax these rules use.
    try:
        cond.compiled = re.compile(pat, flags)
    except re.error as exc:
        cond.error = f"regex does not compile in Python: {exc}"


def parse_rules(path: str | Path) -> dict[str, Rule]:
    text = Path(path).read_text(encoding="utf-8")
    # local_rules.xml has several top-level <group> elements: wrap so it parses.
    root = ET.fromstring(f"<root>{text}</root>")
    rules: dict[str, Rule] = {}
    for el in root.iter("rule"):
        rid = el.get("id", "").strip()
        r = Rule(
            id=rid,
            level=int(el.get("level", "-1")),
            description=(el.findtext("description") or "").strip(),
            xml=ET.tostring(el, encoding="unicode").strip(),
        )
        for tag, target in (("if_sid", r.if_sid), ("if_group", r.if_group)):
            for node in el.findall(tag):
                target.extend(s.strip() for s in (node.text or "").replace(" ", "").split(",") if s.strip())
        for f in el.findall("field"):
            cond = FieldCond(
                name=f.get("name", ""),
                pattern=f.text or "",
                kind=f.get("type", "osregex"),
                negate=f.get("negate", "no").lower() == "yes",
            )
            _compile(cond)
            r.fields.append(cond)
        for mid in el.iter("id"):
            if mid.text:
                r.mitre.append(mid.text.strip())
        if rid in rules:
            r.description += "  [DUPLICATE ID]"
        rules[rid] = r
    return rules


def lint(rules: dict[str, Rule], only: list[str] | None = None) -> dict[str, list[str]]:
    """Return {rule_id: [problems]} - 'ERROR:' blocks grading, 'WARN:' is informational."""
    out: dict[str, list[str]] = {}
    for rid, r in rules.items():
        if only and rid not in only:
            continue
        p: list[str] = []
        if not rid.isdigit():
            p.append("ERROR: rule id is not numeric")
        elif not (CUSTOM_ID_MIN <= int(rid) <= CUSTOM_ID_MAX):
            p.append(f"WARN: id outside custom range {CUSTOM_ID_MIN}-{CUSTOM_ID_MAX}")
        if not 0 <= r.level <= 16:
            p.append("ERROR: level missing or out of range 0-16")
        if not r.description:
            p.append("ERROR: missing <description>")
        if "[DUPLICATE ID]" in r.description:
            p.append("ERROR: duplicate rule id in file")
        if not r.if_sid and not r.if_group:
            p.append("WARN: no if_sid/if_group - rule will be evaluated against every event")
        for c in r.fields:
            if c.error:
                p.append(("ERROR: " if "compile" in c.error else "WARN: ") + f"field {c.name}: {c.error}")
        for m in r.mitre:
            if not MITRE_RE.match(m):
                p.append(f"WARN: MITRE id '{m}' is not in T1234 / T1234.567 form")
        out[rid] = p
    return out


def get_path(doc: dict, dotted: str):
    cur = doc
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def replay_match(rule: Rule, doc: dict) -> bool:
    """Would this rule's field conditions match this indexed event? (approximation)"""
    if not rule.replayable:
        return False
    for c in rule.fields:
        val = get_path(doc, c.doc_path)
        hit = val is not None and c.compiled.search(str(val)) is not None
        if hit == c.negate:
            return False
    return True

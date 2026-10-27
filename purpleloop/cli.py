"""purpleloop command line.

  purpleloop check                       # can we reach the Wazuh indexer?
  purpleloop lint                        # static checks on your rules file
  purpleloop grade cases/X.yaml --since 15m
  purpleloop dataset stats
  purpleloop dataset export --out train.jsonl
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from . import dataset, report
from .grader import grade_case
from .indexer import Indexer
from .rules import lint, parse_rules

log = logging.getLogger("purpleloop")


def load_env(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def load_cfg(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        raise SystemExit(f"config not found: {p} (copy config.example.yaml to config.yaml)")
    cfg = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    cfg["_base"] = p.resolve().parent
    return cfg


def resolve(cfg: dict, rel: str) -> Path:
    q = Path(rel)
    return q if q.is_absolute() else cfg["_base"] / q


def load_case(path: str) -> dict:
    case = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    for key in ("id", "title", "technique", "agent", "expected_rules"):
        if key not in case:
            raise SystemExit(f"case {path} is missing '{key}'")
    # YAML reads 100200 as an int; normalize every rule-keyed map to string ids.
    case["expected_rules"] = [str(r) for r in case["expected_rules"]]
    for k in ("rules_meta", "rule_overrides"):
        case[k] = {str(i): v for i, v in (case.get(k) or {}).items()}
    case.setdefault("test", {"performed_by": "human", "how": ""})
    return case


def parse_since(s: str) -> timedelta:
    m = re.fullmatch(r"(\d+)\s*([mhd])", s.strip())
    if not m:
        raise SystemExit("--since must look like 15m, 2h or 1d")
    n, unit = int(m.group(1)), m.group(2)
    return {"m": timedelta(minutes=n), "h": timedelta(hours=n), "d": timedelta(days=n)}[unit]


def parse_time(s: str) -> datetime:
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.astimezone()  # naive -> local time


def indexer_from(cfg: dict) -> Indexer:
    ic = cfg["indexer"]
    env = ic.get("password_env", "PURPLELOOP_INDEXER_PASSWORD")
    pw = os.environ.get(env, "")
    if not pw:
        raise SystemExit(f"set {env} (in the environment or .env)")
    return Indexer(ic["url"], ic.get("user", "purpleloop"), pw, bool(ic.get("verify_tls", False)))


def cmd_check(cfg: dict, _a) -> int:
    ix = indexer_from(cfg)
    print(f"indexer reachable, version {ix.ping()}")
    now = datetime.now(timezone.utc)
    for name in ("alerts_index", "archives_index"):
        idx = cfg["indexer"].get(name)
        print(f"{idx}: {ix.count(idx, '*', now - timedelta(hours=24), now)} docs in the last 24h")
    return 0


def cmd_lint(cfg: dict, a) -> int:
    rules = parse_rules(resolve(cfg, a.rules or cfg.get("rules_file", "rules/local_rules.xml")))
    problems = lint(rules)
    errors = 0
    for rid, ps in problems.items():
        status = "ERROR" if any(p.startswith("ERROR") for p in ps) else ("warn" if ps else "ok")
        errors += status == "ERROR"
        print(f"{rid:>7}  {status:<5}  {rules[rid].description[:70]}")
        for p in ps:
            print(f"         - {p}")
    vc = (cfg.get("wazuh") or {}).get("validate_cmd")
    if vc:
        print(f"\nremote validation: {vc}")
        rc = subprocess.run(vc, shell=True).returncode
        print("remote validation " + ("OK" if rc == 0 else f"FAILED (exit {rc})"))
        errors += rc != 0
    return 1 if errors else 0


def cmd_grade(cfg: dict, a) -> int:
    case = load_case(a.case)
    rules_path = resolve(cfg, cfg.get("rules_file", "rules/local_rules.xml"))
    rules = parse_rules(rules_path)
    if a.start:
        start = parse_time(a.start)
        end = parse_time(a.end) if a.end else datetime.now(timezone.utc)
    else:
        end = datetime.now(timezone.utc)
        start = end - parse_since(a.since)
    rep = grade_case(indexer_from(cfg), rules, case, cfg, start, end)

    reports = resolve(cfg, cfg.get("reports_dir", "reports"))
    reports.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    md = reports / f"{case['id']}-{stamp}.md"
    md.write_text(report.render(rep), encoding="utf-8")
    (reports / f"{case['id']}-{stamp}.json").write_text(json.dumps(rep, indent=2), encoding="utf-8")

    if not a.no_record:
        n = dataset.append_records(resolve(cfg, cfg.get("dataset_file", "data/graded.jsonl")),
                                   rep, {rid: r.xml for rid, r in rules.items()}, case)
        log.info("recorded %d result(s) to the dataset", n)

    print(report.render(rep))
    print(f"report: {md}")
    return 0 if rep["overall"] == "PASS" else 1


def cmd_dataset(cfg: dict, a) -> int:
    recs = dataset.load(resolve(cfg, cfg.get("dataset_file", "data/graded.jsonl")))
    excl = a.exclude_provenance or (cfg.get("training") or {}).get("exclude_provenance", ["claude"])
    examples, stats = dataset.export_training(recs, excl, include_noisy=a.include_noisy)
    if a.action == "export":
        out = Path(a.out)
        out.write_text("".join(json.dumps(e, ensure_ascii=False) + "\n" for e in examples), encoding="utf-8")
        print(f"wrote {len(examples)} training example(s) to {out}")
    stats["excluded_provenance"] = excl
    print(json.dumps(stats, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="purpleloop", description="Grade Wazuh detections with evidence.")
    ap.add_argument("--config", default=os.environ.get("PURPLELOOP_CONFIG", "config.yaml"))
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check", help="test indexer access")
    p = sub.add_parser("lint", help="static checks on the rules file")
    p.add_argument("--rules")
    p = sub.add_parser("grade", help="grade a case after you ran its test")
    p.add_argument("case")
    p.add_argument("--since", default="15m", help="window ending now, e.g. 15m (default)")
    p.add_argument("--start", help="window start (ISO time); overrides --since")
    p.add_argument("--end", help="window end (ISO time), default now")
    p.add_argument("--no-record", action="store_true", help="don't append to the dataset")
    p = sub.add_parser("dataset", help="training dataset tools")
    p.add_argument("action", choices=["stats", "export"])
    p.add_argument("--out", default="train.jsonl")
    p.add_argument("--exclude-provenance", nargs="*")
    p.add_argument("--include-noisy", action="store_true")
    a = ap.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    cfg = load_cfg(a.config)
    load_env(cfg["_base"] / ".env")
    return {"check": cmd_check, "lint": cmd_lint, "grade": cmd_grade, "dataset": cmd_dataset}[a.cmd](cfg, a)


if __name__ == "__main__":
    sys.exit(main())

"""Markdown report: the evidence a reviewer (or a GitHub reader) needs, nothing more."""

from __future__ import annotations

ICON = {"PASS": "✅", "NOISY": "🟡", "FAIL": "❌"}


def render(rep: dict) -> str:
    c = rep["case"]
    test = c.get("test") or {}
    lines = [
        f"# {ICON.get(rep['overall'], '')} {c['id']}: {c['title']}",
        "",
        f"- **Technique:** {c['technique']}",
        f"- **Target:** `{c['agent']}`",
        f"- **Test (run by {test.get('performed_by', 'human')}):** {test.get('how', '')}",
        f"- **Window:** {rep['window']['start']} → {rep['window']['end']}",
        f"- **Overall:** **{rep['overall']}**  ·  graded {rep['graded_at']} by PurpleLoop {rep['purpleloop_version']}",
        "",
        "| Rule | Verdict | Diagnosis | Alerts in window | Raw events / replay matches | FP estimate |",
        "|---|---|---|---|---|---|",
    ]
    for r in rep["rules"]:
        b = r.get("baseline") or {}
        fp = (f"{b.get('matches_per_day', 0)}/day ({b.get('confidence', 'none')} confidence, "
              f"{b.get('covered_hours', 0)}h)") if b else "n/a"
        lines.append(f"| {r['rule_id']} | {ICON.get(r['verdict'], '')} {r['verdict']} | {r['diagnosis']} | "
                     f"{r['alerts_in_window']} | "
                     + ("sensor alert" if r.get("kind") == "signal"
                        else f"{r['candidates_in_window']} / {r['replay_matches_in_window']}")
                     + f" | {fp} |")
    for r in rep["rules"]:
        lines += ["", f"## {'Signal' if r.get('kind') == 'signal' else 'Rule'} {r['rule_id']}: {r.get('description', '')}", "",
                  f"**{r['verdict']}**: {r['reason']}", ""]
        if r.get("sample_alert"):
            lines += [f"- First alert: `{r['first_alert']}`: {r['sample_alert']}"]
        lines += [f"- Candidate query: `{r.get('candidate_query', '')}`"]
        if r.get("lint"):
            lines += ["- Lint:"] + [f"  - {p}" for p in r["lint"]]
        if r["diagnosis"] in ("MISMATCH", "SHADOWED") and r.get("sample_values"):
            lines += ["- Field values seen in the window (compare with the rule's patterns):"]
            for k, vals in r["sample_values"].items():
                for v in vals:
                    lines.append(f"  - `{k}` = `{v}`")
        b = r.get("baseline") or {}
        if b and r.get("kind") == "signal":
            lines += [f"- Baseline: {b['alerts_outside_window']} matching alerts in the {b['covered_hours']}h "
                      f"the sensor reported before the test (requested {b['days_requested']}d)"]
        elif b:
            lines += [f"- Baseline: {b['candidates']} candidate events over {b['covered_hours']}h "
                      f"(requested {b['days_requested']}d); replay matches {b['replay_matches']}; "
                      f"real alerts outside window {b['alerts_outside_window']}"
                      + ("; **truncated**" if b.get("truncated") else "")]
    lines += ["", "> Replay evaluates the rule's pcre2 `<field>` conditions against stored events and "
              "approximates parent rules with the candidate query. Alerts are ground truth; replay explains them."]
    return "\n".join(lines) + "\n"

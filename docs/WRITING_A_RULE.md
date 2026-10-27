# Writing a detection, the PurpleLoop way

A repeatable method for going from "I want to catch X" to a graded rule. Follow the steps in
order; each one produces something you write down. That record becomes your case file and your
write-up.

## 1. Hypothesis
Write one sentence: **"When an attacker does ___, the endpoint will show ___."**
Name the MITRE ATT&CK technique ID. Read the technique's page on attack.mitre.org, and note how
it can be done in **more than one way** (different tools, different paths).

## 2. Run the test once, before writing anything
Pick a published test for the technique (Atomic Red Team lists them per technique ID). Read what
it does with `-ShowDetailsBrief` first. Run it on your lab machine. Write down the exact time.

## 3. Find the telemetry
In Wazuh **Discover → `wazuh-archives-*`**, filter to your agent and a few minutes around the
test. Answer:
- Which **event ID** shows the behavior (Sysmon 1 = process, 11 = file, 13 = registry...)?
- Which **fields** carry the evidence (`image`, `commandLine`, `targetObject`, `parentImage`...)?
- What does the value look like **exactly**, including how backslashes are stored?

If nothing shows up, stop: you have a **logging gap**, not a rule problem. Fix logging first.

## 4. Check what already fires
In `wazuh-alerts-*`, look at the same window. Did a built-in rule alert? Is it the **right
technique**, or a coincidence? Note the built-in rules involved; you may need them as parents.

## 5. Find the parent rule
Your rule hangs off a parent (`<if_sid>`). Find which built-in rule handles that event type:
```bash
sudo grep -rnF -B3 '<field name="win.system.eventID">^13$</field>' /var/ossec/ruleset/rules/
```
Also check for rules that attach to the same **group** (`<if_group>`) and might take the event
first. Those become extra parents.

## 6. Write the rule: behavior first
- Match the **behavior** (what changed), not the **tool** (which program did it), where you can.
- Use `type="pcre2"` and `(?i)`. Match the stored form of paths (`\\+` handles any number of
  backslashes).
- Put the evidence in the description: `$(win.eventdata.image)`, `$(win.eventdata.targetObject)`.
- Add the MITRE ID. Use an ID in your own range (for example 100300+).

## 7. Lint, deploy, restart
```bash
purpleloop lint
sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
```

## 8. Test it, then try to beat it
Run the published test again, **and** a variant that does the same thing a different way (a
different tool, a different path, a different user). A rule that only catches one tool is
brittle.

## 9. Grade it
Write a case file (copy `cases/T1547.001-runkey.yaml`), set `provenance` honestly, then:
```bash
purpleloop grade cases/<your-case>.yaml --since 15m
```
Fix whatever the diagnosis points at, and grade again until it passes.

## 10. Tune and write it up
Look at what matches on normal activity. For each benign source, decide: add an exception, or
accept the noise. Write down the decision and **the risk you accepted**. Your write-up:
what you hypothesized, what you found, the gap, the rule, how you validated it, known false
positives, the trade-off.

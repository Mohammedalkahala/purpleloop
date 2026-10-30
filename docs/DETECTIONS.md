# Detections

Rules written hands-on against live Atomic Red Team / Caldera attacks in the lab,
following docs/WRITING_A_RULE.md. Each was validated with PurpleLoop.

## 100202 — PowerShell launched from a user-writable folder

**Technique:** T1059.001 (PowerShell)  ·  **Level:** 12

**Hypothesis.** When an attacker runs PowerShell from an implant in a user-writable
folder, the endpoint shows a process-creation event where `image` is powershell.exe
and `parentImage` is under C:\Users\Public.

**How I found it.** Ran a Caldera Discovery operation on office01. Reading the raw
Sysmon telemetry, every PowerShell command was launched by the agent at
`C:\Users\Public\splunkd.exe`. The built-in rules only alerted on *command content*
(process discovery, AV discovery); none alerted on the parent-child relationship.
An implant running an uncatalogued PowerShell command would have slipped through.

**The rule.** Chains off Wazuh 61603 (Sysmon event 1). Matches `image` =
powershell.exe AND `parentImage` under C:\Users\Public. Catches the implant no
matter what command it runs.

**Validation.** DETECTED, 8 alerts, on a live Caldera run. PurpleLoop reported
NOISY (9/day), but all baseline matches were prior red-team runs — the lab has no
clean baseline period. Expected production false positives: ~0, since legitimate
software does not launch PowerShell from C:\Users\Public.

## 100203 — Tune: silence benign taskschd.dll loads

**Tames:** Wazuh 92154 (loaded taskschd.dll, T1053.005)  ·  **Level:** 0

**Problem.** 92154 fired dozens of times a day. Every hit was a legitimate,
Microsoft-signed process (taskhostw.exe, svchost.exe, sppsvc.exe, MicrosoftEdgeUpdate.exe,
SoftLandingTask.exe, MoUsoCoreWorker.exe) loading the scheduler DLL as normal Windows
housekeeping — low fidelity, high volume.

**Iteration.** First tune matched only taskhostw.exe; the data then showed six other
benign signed-Microsoft loaders. Broadened to match the shared benign signal:
`signature` = Microsoft Windows AND `signatureStatus` = Valid.

**Trade-off.** The rule stays armed for the real threat — an unsigned or
non-Microsoft process loading taskschd.dll still fires. Scheduled-task *abuse* is
detected through stronger signals (task creation, schtasks.exe, registry writes),
so muting this weak image-load signal for signed-Microsoft binaries costs little.

**Validation.** After deploy, zero new 92154 alerts from signed-Microsoft loaders.

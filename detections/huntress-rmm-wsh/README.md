# Detection #2: Rogue ScreenConnect → Windows Script Host (Huntress, Sep 2026)

| | |
|---|---|
| **Source** | Huntress, "Rogue ScreenConnect Installations Across Unrelated Hosts Suggest Worm-Like Activity" (Sep 2026): https://www.huntress.com/blog/rogue-screenconnect-installations |
| **Behaviour** | A rogue ScreenConnect client (`ScreenConnect.WindowsClient.exe`) repeatedly spawns `wscript.exe` to run `1.vbs` to `4.vbs` from a temp folder. Stage 4 runs `%TEMP%\runner.ps1`, and persistence is a Run key `WindowsServiceHost` → `WindowsServiceHost.vbs`. |
| **MITRE ATT&CK** | T1219 (Remote Access Software), T1059.005 (VBScript), T1059.001 (PowerShell), T1547.001 (Run Keys) |
| **Telemetry** | Sysmon Event 1 (process creation) and Event 13 (registry value set), via the Wazuh agent (group `sysmon`) |
| **Test target** | office02 (VM 201), restored to the `baseline` snapshot after each test |
| **Provenance** | Rules and simulation drafted with AI, reviewed by a human; validation status is in the grade table below |
| **Status** | ⏳ draft, not yet graded |

## Rules

| ID | Level | What it catches | Sigma |
|---|---|---|---|
| 100510 | 12 | A ScreenConnect client spawns wscript or cscript | `sigma/screenconnect_spawns_script_host.yml` |
| 100511 | 14 | The above 3+ times in 2 minutes on one host (the "repeatedly spawns" pattern) | (correlation) |
| 100512 | 10 | wscript or cscript runs a single-digit `N.vbs` from Temp or a ScreenConnect folder | `sigma/numbered_vbs_from_temp.yml` |
| 100513 | 10 | wscript or cscript starts PowerShell `-File` on a `.ps1` in Temp | (Wazuh only for now) |
| 100514 | 12 | A Run key value launches a `.vbs` | `sigma/run_key_vbscript.yml` |

## The simulation (`sim/simulate.ps1`): safe by design
It reproduces the **telemetry**, not the malware:
- There are no downloads, no real ScreenConnect, no payload, no changes to Defender or memory integrity, and nothing is killed.
- The "ScreenConnect client" is a **renamed copy of powershell.exe**, so the parent and child process names match the Huntress chain.
- The four VBScripts pass state through `%TEMP%\value.txt`, `map.txt` and `out.enc` like the real ones. Their content is placeholder text.
- `runner.ps1` only sets the `WindowsServiceHost` Run key to a do-nothing `.vbs`.
- Everything is removed afterwards. Use `-CleanupOnly` to remove leftovers.
- It refuses to run on any host other than OFFICE02 or a later test VM.

**Honest limit:** the parent is an emulated binary. Its `OriginalFileName` is PowerShell's, not ScreenConnect's. Rules 100510 and 100511 match on the image name, which is what the real chain shows. A later step is a level-2 validation with a genuine ScreenConnect trial client.

## Grade (receipts)

| Date | Target | Expected | Result | Grade |
|---|---|---|---|---|
| (pending) | office02 | 100510 ×4, 100511, 100512 ×4, 100513, 100514 | | |

## False positives and tuning
- **100510:** technicians who really do run VBScript through ScreenConnect's command toolbox. Baseline it per environment, and add an exception per technician script path if needed.
- **100512:** rare. Some old logon scripts use one-character names.
- **100514:** some legacy software starts helper `.vbs` files at logon. Allow-list them by full path.

## Undo
- On the test VM: `simulate.ps1 -CleanupOnly`, or restore the `baseline` snapshot.
- Rules: remove the `huntress_rmm_wsh` group from `local_rules.xml` and restart the manager.

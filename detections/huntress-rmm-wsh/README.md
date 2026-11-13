# Detection #2: Rogue ScreenConnect → Windows Script Host (Huntress, Sep 2026)

| | |
|---|---|
| **Source** | Huntress, "Rogue ScreenConnect Installations Across Unrelated Hosts Suggest Worm-Like Activity" (Sep 2026): https://www.huntress.com/blog/rogue-screenconnect-installations |
| **Behaviour** | A rogue ScreenConnect client (`ScreenConnect.WindowsClient.exe`) repeatedly spawns `wscript.exe` to run `1.vbs` to `4.vbs` from a temp folder. Stage 4 runs `%TEMP%\runner.ps1`, and persistence is a Run key `WindowsServiceHost` → `WindowsServiceHost.vbs`. |
| **MITRE ATT&CK** | T1219 (Remote Access Software), T1059.005 (VBScript), T1059.001 (PowerShell), T1547.001 (Run Keys) |
| **Telemetry** | Sysmon Event 1 (process creation) and Event 13 (registry value set), via the Wazuh agent (group `sysmon`) |
| **Test target** | office02 (VM 201), restored to the `baseline` snapshot after each test |
| **Provenance** | Rules and simulation drafted with AI, reviewed by a human; validation status is in the grade table below |
| **Status** | ✅ core chain PASS (run 4) · ✅ robustness: 7/7 variants handled after hardening (V7 = documented gap) · ✅ low-telemetry: PASS without Sysmon (100517, 100518) |

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
| 2026-11-13 run 1 | office02 | 4 alerts from 100510/100511, 100513 ×1, 100514 ×1 | 4 wscript alerts ✅; 100513 and 100514 claimed by built-in 92029 / 92301 | FAIL → fixed (parents 61603+92029, 61615+92301) |
| 2026-11-13 run 2–3 | office02 | same | wscript alerts ✅; 100513/100514 still silent: regexes assumed single backslashes, Wazuh stores `\\` and `\"` | FAIL → fixed (`\\+` patterns) |
| 2026-11-13 run 4 | office02 | 4 wscript alerts (100510 ×3 + 100511 ×1), 100513 ×1, 100514 ×1 | exactly as expected | **PASS** |

**Note on 100512:** in the full chain the 4 wscript events go to 100510 (ScreenConnect parent). 100512 is the backstop that fires when the parent link is broken (e.g. `cmd /c wscript`), so it is expected to stay silent in this run.

**Lesson learned:** Wazuh stores Windows eventchannel paths with doubled backslashes and escaped quotes, so patterns use `\\+` and avoid quote anchors.

**Note on built-in overlap:** Wazuh's 92029 and 92301 match the PowerShell and Run-key events first, so 100513/100514 hang off those rules as well as the Sysmon base rules.

## Beyond the original post

### 1. Robustness: how easy is the obvious rule to dodge? (`sim/variants.ps1`)
Each variant is harmless and tags its command line with `PLSIM-Vn`. The "expected" column is a prediction; the "result" column is filled in from the run.

| Variant | Change an attacker could make | Expected to fire | Result |
|---|---|---|---|
| V1 | `cscript` instead of `wscript` | 100510 | ✅ 100510 |
| V2 | script renamed `update.vbs` | 100510 (100512 misses: not a numbered name) | ✅ 100510 |
| V3 | JScript `payload.js` | 100510 | ✅ caught as 100511 (3rd ScreenConnect→script host in 2 min, across variants) |
| V4 | `cmd /c wscript ...` breaks the parent link | 100510 misses → **100516** (hardened) + 100512 backstop | ⚠️ 100510 missed as predicted; first run caught only by the 100512 backstop (L10) + built-in 92052 (L4). ✅ After hardening: **100516** + 100512 |
| V5 | `ScreenConnect.ClientService.exe` as parent | 100510 | ✅ 100510 |
| V6 | `mshta vbscript:...` | 100510 misses → **100515** (hardened) | ⚠️ mshta launched from ScreenConnect and none of 100510–100514 fired (the inline payload itself failed on a test-harness quoting bug; Defender logged nothing). ✅ After hardening: **100515** |
| V7 | PowerShell straight from ScreenConnect | nothing: indistinguishable from normal technician use (documented gap) | ✅ gap confirmed: only built-in 91816 (L4) |

Hardened rules: `wazuh/huntress-rmm-wsh_hardened_rules.xml` (100515, 100516).

**Emulation side effects (not real-world signals):** because the fake client is a renamed powershell.exe copied to disk, built-in rules 92151 ("binary loaded PowerShell automation library", L12), 92213 ("executable dropped in folder commonly used by malware", L15) and 92203 fire on every run. A genuine ScreenConnect client would not trigger these; do not count them as detection coverage.

### 2. Low telemetry: no Sysmon, no EDR (`sim/lowtel-setup.ps1`)
What a small business can still see using only free, built-in Windows logging: Security **4688** with command lines, and PowerShell script-block logging **4104**.
Rules: `wazuh/huntress-rmm-wsh_lowtel_rules.xml` (100517 = 4688 version of 100510; 100518 = 4104 version of the Run-key persistence). Their parent rule IDs must be confirmed on the manager before deploying.

| Stage of the chain | With Sysmon | Built-in logging only (result 2026-11-13) |
|---|---|---|
| ScreenConnect → wscript ×4 | 100510 ×3 + 100511 | ✅ **100517 ×4** (Security 4688) |
| wscript → PowerShell runner.ps1 | 100513 | ✅ visible in the 4104 script block (no dedicated rule yet) |
| Run key → .vbs | 100514 | ✅ **100518** (4104), one second *before* Sysmon's registry event, because the script block is logged before it runs |

**Takeaway:** an organisation with no Sysmon and no EDR can still catch this chain with two free Windows settings (process-creation auditing with command lines, and PowerShell script-block logging) plus these two rules.

### 3. Giving back
- **Atomic Red Team:** `atomic/T1059.005-rmm-script-host-chain.yaml`, a proposed test for Red Canary's Atomic Red Team.
- **SigmaHQ:** the three Sigma rules in `sigma/`, crediting the Huntress post.

## False positives and tuning
- **100510:** technicians who really do run VBScript through ScreenConnect's command toolbox. Baseline it per environment, and add an exception per technician script path if needed.
- **100512:** rare. Some old logon scripts use one-character names.
- **100514:** some legacy software starts helper `.vbs` files at logon. Allow-list them by full path.

## Undo
- On the test VM: `simulate.ps1 -CleanupOnly`, or restore the `baseline` snapshot.
- Rules: remove the `huntress_rmm_wsh` group from `local_rules.xml` and restart the manager.

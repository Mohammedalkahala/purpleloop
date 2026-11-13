<#
PurpleLoop simulation: Huntress "rogue ScreenConnect -> wscript -> 1..4.vbs" chain (Sep 2026).
SAFE BY DESIGN: no downloads, no real ScreenConnect, no malware, no Defender changes, nothing killed.
It reproduces the TELEMETRY only:
  1. a process named ScreenConnect.WindowsClient.exe (a renamed copy of powershell.exe) spawns wscript.exe 4 times
  2. wscript runs 1.vbs..4.vbs from a ScreenConnect-style temp folder; they pass state through %TEMP%\value.txt, map.txt, out.enc
  3. 4.vbs starts PowerShell on %TEMP%\runner.ps1
  4. runner.ps1 sets HKCU\...\Run "WindowsServiceHost" -> a do-nothing .vbs in %APPDATA% (persistence telemetry)
  5. everything is removed again (unless -KeepArtifacts)
Run elevated on the TEST VM only (office02):  powershell -ExecutionPolicy Bypass -File simulate.ps1
Undo for anything left behind:                powershell -ExecutionPolicy Bypass -File simulate.ps1 -CleanupOnly
#>
param([switch]$KeepArtifacts, [switch]$CleanupOnly)
$ErrorActionPreference = 'Stop'
$tag      = 'PURPLELOOP-SIM huntress-rmm-wsh'
$fakeDir  = Join-Path ${env:ProgramFiles(x86)} 'ScreenConnect Client (purpleloop-sim)'
$fakeExe  = Join-Path $fakeDir 'ScreenConnect.WindowsClient.exe'
$stage    = Join-Path $env:TEMP 'ScreenConnect\26.1.0.0\purpleloop-sim'
$persist  = Join-Path $env:APPDATA 'WindowsServiceHost.vbs'
$runKey   = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'

function Cleanup {
  Remove-ItemProperty -Path $runKey -Name WindowsServiceHost -ErrorAction SilentlyContinue
  Remove-Item $persist, $fakeDir, (Join-Path $env:TEMP 'ScreenConnect'), `
    "$env:TEMP\value.txt", "$env:TEMP\map.txt", "$env:TEMP\out.enc", "$env:TEMP\runner.ps1", "$env:TEMP\purpleloop-sim.done" `
    -Recurse -Force -ErrorAction SilentlyContinue
  "cleanup done"
}
if ($CleanupOnly) { Cleanup; return }
if ($env:COMPUTERNAME -notmatch '^OFFICE0[2-9]$') { throw "Refusing to run on $env:COMPUTERNAME: test VMs only (office02+)." }

# --- build the staging scripts (each one harmless, each one waits for the previous stage's file, like the real chain)
New-Item $stage -ItemType Directory -Force | Out-Null
$wait = 'Do While Not fso.FileExists(sh.ExpandEnvironmentStrings("%TEMP%\{0}")) : WScript.Sleep 500 : Loop'
$hdr  = "' $tag`r`nSet fso = CreateObject(""Scripting.FileSystemObject"") : Set sh = CreateObject(""WScript.Shell"")`r`n"
@{
 '1.vbs' = $hdr + @'
' stage 1: host profiling (read-only WMI queries), then write a 3-bit state value
Set wmi = GetObject("winmgmts:\\.\root\cimv2")
For Each cs In wmi.ExecQuery("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem") : ram = cs.TotalPhysicalMemory : Next
On Error Resume Next
Set sc2 = GetObject("winmgmts:\\.\root\SecurityCenter2")
For Each av In sc2.ExecQuery("SELECT displayName FROM AntiVirusProduct") : avs = avs & av.displayName & ";" : Next
On Error GoTo 0
Set f = fso.CreateTextFile(sh.ExpandEnvironmentStrings("%TEMP%\value.txt"), True) : f.WriteLine "000" : f.Close
'@
 '2.vbs' = $hdr + ($wait -f 'value.txt') + "`r`n" + @'
' stage 2: (real one downloads from Dropbox) - here we only write a local placeholder
Set f = fso.CreateTextFile(sh.ExpandEnvironmentStrings("%TEMP%\map.txt"), True) : f.WriteLine "PURPLELOOP-SIM map" : f.Close
'@
 '3.vbs' = $hdr + ($wait -f 'map.txt') + "`r`n" + @'
' stage 3: (real one downloads the encrypted payload) - here a local dummy file
Set f = fso.CreateTextFile(sh.ExpandEnvironmentStrings("%TEMP%\out.enc"), True) : f.WriteLine "PURPLELOOP-SIM not a payload" : f.Close
'@
 '4.vbs' = $hdr + ($wait -f 'out.enc') + "`r`n" + @'
' stage 4: launch PowerShell on %TEMP%\runner.ps1 (hidden, wait)
sh.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & sh.ExpandEnvironmentStrings("%TEMP%\runner.ps1") & """", 0, True
'@
}.GetEnumerator() | ForEach-Object { Set-Content -Path (Join-Path $stage $_.Key) -Value $_.Value -Encoding ascii }

Set-Content "$env:TEMP\runner.ps1" -Encoding ascii -Value @"
# $tag : persistence telemetry only. The real runner.ps1 decrypts and runs a payload; this one does not.
Set-Content -Path '$persist' -Value "' $tag - does nothing" -Encoding ascii
Set-ItemProperty -Path '$runKey' -Name WindowsServiceHost -Value ('wscript.exe "' + '$persist' + '"')
Set-Content -Path "`$env:TEMP\purpleloop-sim.done" -Value (Get-Date -Format o)
"@

# --- the fake ScreenConnect client: a renamed copy of powershell.exe that spawns wscript.exe 4 times
New-Item $fakeDir -ItemType Directory -Force | Out-Null
Copy-Item "$PSHOME\powershell.exe" $fakeExe -Force
$t0 = Get-Date
$child = "foreach (`$i in 1..4) { Start-Process wscript.exe -ArgumentList ('//B //Nologo ""' + '$stage' + '\' + `$i + '.vbs""') }; " +
         "`$d = Join-Path `$env:TEMP 'purpleloop-sim.done'; `$n = 0; while (-not (Test-Path `$d) -and `$n -lt 120) { Start-Sleep 1; `$n++ }"
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($child))   # avoids PS 5.1 quote mangling
& $fakeExe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $enc

$ok = Test-Path "$env:TEMP\purpleloop-sim.done"
[pscustomobject]@{
  Test        = $tag
  Started     = $t0.ToString('o')
  Finished    = (Get-Date).ToString('o')
  ChainDone   = $ok
  RunKeySet   = [bool](Get-ItemProperty $runKey -Name WindowsServiceHost -ErrorAction SilentlyContinue)
  Host        = $env:COMPUTERNAME
} | Format-List
if (-not $KeepArtifacts) { Start-Sleep 5; Cleanup }
if (-not $ok) { exit 1 }

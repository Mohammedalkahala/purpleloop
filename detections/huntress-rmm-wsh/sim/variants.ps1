<#
PurpleLoop robustness test for detection #2: "how easy is the obvious rule to dodge?"
Same safety rules as simulate.ps1: harmless payloads (they only write a marker file), no downloads, test VMs only.
Each variant tags its command line with PLSIM-Vn so every alert can be traced to the variant that caused it.
  V1 cscript instead of wscript             V4 cmd /c wscript (breaks the parent link)
  V2 renamed script (update.vbs)            V5 ScreenConnect.ClientService.exe as the parent (SYSTEM-style service)
  V3 JScript (.js) instead of VBScript      V6 mshta running inline VBScript
  V7 PowerShell straight from ScreenConnect (what a technician also does: expected gap, documented)
Run elevated on office02:   powershell -ExecutionPolicy Bypass -File variants.ps1 [-Only V4,V6]
Cleanup only:               powershell -ExecutionPolicy Bypass -File variants.ps1 -CleanupOnly
#>
param([string[]]$Only, [switch]$CleanupOnly)
$ErrorActionPreference = 'Stop'
$base   = Join-Path ${env:ProgramFiles(x86)} 'ScreenConnect Client (purpleloop-sim)'
$stage  = Join-Path $env:TEMP 'ScreenConnect\26.1.0.0\purpleloop-var'
$marker = Join-Path $env:TEMP 'purpleloop-var.log'
function Cleanup { Remove-Item $base, (Join-Path $env:TEMP 'ScreenConnect'), $marker -Recurse -Force -ErrorAction SilentlyContinue; 'cleanup done' }
if ($CleanupOnly) { Cleanup; return }
if ($env:COMPUTERNAME -notmatch '^OFFICE0[2-9]$') { throw "Refusing to run on $env:COMPUTERNAME: test VMs only." }

New-Item $base, $stage -ItemType Directory -Force | Out-Null
$client  = Join-Path $base 'ScreenConnect.WindowsClient.exe'; Copy-Item "$PSHOME\powershell.exe" $client -Force
$service = Join-Path $base 'ScreenConnect.ClientService.exe'; Copy-Item "$PSHOME\powershell.exe" $service -Force
$vbs = 'Set f = CreateObject("Scripting.FileSystemObject").OpenTextFile(CreateObject("WScript.Shell").ExpandEnvironmentStrings("%TEMP%\purpleloop-var.log"), 8, True) : f.WriteLine WScript.Arguments(0) & " ran" : f.Close'
$js  = 'var f = new ActiveXObject("Scripting.FileSystemObject").OpenTextFile(new ActiveXObject("WScript.Shell").ExpandEnvironmentStrings("%TEMP%\\purpleloop-var.log"), 8, true); f.WriteLine(WScript.Arguments(0) + " ran"); f.Close();'
Set-Content (Join-Path $stage '1.vbs') $vbs -Encoding ascii
Set-Content (Join-Path $stage 'update.vbs') $vbs -Encoding ascii
Set-Content (Join-Path $stage 'payload.js') $js -Encoding ascii

$v = [ordered]@{
  V1 = @($client,  "Start-Process cscript.exe -ArgumentList '//B //Nologo `"$stage\1.vbs`" PLSIM-V1' -Wait")
  V2 = @($client,  "Start-Process wscript.exe -ArgumentList '//B //Nologo `"$stage\update.vbs`" PLSIM-V2' -Wait")
  V3 = @($client,  "Start-Process wscript.exe -ArgumentList '//B //Nologo `"$stage\payload.js`" PLSIM-V3' -Wait")
  V4 = @($client,  "Start-Process cmd.exe -ArgumentList '/c wscript.exe //B //Nologo `"$stage\1.vbs`" PLSIM-V4' -Wait")
  V5 = @($service, "Start-Process wscript.exe -ArgumentList '//B //Nologo `"$stage\1.vbs`" PLSIM-V5' -Wait")
  V6 = @($client,  "Start-Process mshta.exe -ArgumentList 'vbscript:Execute(`"CreateObject(`"`"WScript.Shell`"`").Run `"`"cmd /c echo PLSIM-V6 ran>>%TEMP%\purpleloop-var.log`"`",0:close`")' -Wait")
  V7 = @($client,  "Start-Process powershell.exe -ArgumentList '-NoProfile -Command `"Add-Content `$env:TEMP\purpleloop-var.log ''PLSIM-V7 ran''`"' -Wait")
}
$results = foreach ($k in $v.Keys) {
  if ($Only -and $k -notin $Only) { continue }
  $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($v[$k][1]))
  $t = (Get-Date).ToUniversalTime().ToString('HH:mm:ss.fff')
  & $v[$k][0] -NoProfile -ExecutionPolicy Bypass -EncodedCommand $enc
  Start-Sleep 2
  [pscustomobject]@{ Variant = $k; StartedUtc = $t; Ran = [bool](Select-String -Path $marker -Pattern "PLSIM-$k ran" -Quiet -ErrorAction SilentlyContinue) }
}
$results | Format-Table -AutoSize
Start-Sleep 3; Cleanup

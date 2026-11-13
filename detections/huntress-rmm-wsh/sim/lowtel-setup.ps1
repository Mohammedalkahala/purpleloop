<#
Detection #2, low-telemetry test: what can you see WITHOUT Sysmon or an EDR?
Turns on the built-in Windows logging that a small business can enable for free:
  - Security 4688 "process created", including the command line
  - PowerShell script-block logging (4104)
Run elevated on office02 once, then run simulate.ps1 again and compare the Security/PowerShell alerts with the Sysmon ones.
Undo:  powershell -ExecutionPolicy Bypass -File lowtel-setup.ps1 -Undo
#>
param([switch]$Undo)
$ErrorActionPreference = 'Stop'
$audit = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
$sbl   = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
if ($Undo) {
  auditpol /set /subcategory:"Process Creation" /success:disable | Out-Null
  Remove-ItemProperty $audit -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue
  Remove-ItemProperty $sbl -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue
  'built-in logging settings reverted'; return
}
auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
New-Item $audit -Force | Out-Null; Set-ItemProperty $audit -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord
New-Item $sbl -Force | Out-Null;   Set-ItemProperty $sbl -Name EnableScriptBlockLogging -Value 1 -Type DWord
auditpol /get /subcategory:"Process Creation"
'4688 with command line + PowerShell 4104 enabled'

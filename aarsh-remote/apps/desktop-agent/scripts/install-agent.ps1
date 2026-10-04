<#
.SYNOPSIS  Installs the Aarsh Remote agent as a Windows service (run in an elevated PowerShell).
.DESCRIPTION
  * Copies the published agent to C:\Program Files\AarshRemote
  * Creates C:\ProgramData\AarshRemote (config/state/logs)
  * Registers the service "AarshRemoteAgent" (automatic, delayed start; restarts itself on failure)
  * Runs the pairing screen, then starts the service
  It does NOT touch the firewall (the agent only makes outbound connections), Windows Defender, power settings, or anything else.
  NOT YET TESTED ON WINDOWS — see docs/windows-agent.md "Verification checklist".
.EXAMPLE   .\install-agent.ps1 -Source .\publish -Server https://remote.example.com -Name NGP-WORKSTATION
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string] $Source,
  [Parameter(Mandatory)] [string] $Server,
  [string] $Name = $env:COMPUTERNAME,
  [switch] $SkipPairing
)
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run this from an elevated (Administrator) PowerShell.'
}
$exeName = 'AarshRemote.Agent.exe'
if (-not (Test-Path (Join-Path $Source $exeName))) { throw "$exeName not found in $Source (publish it first: see docs/windows-agent.md)" }

$install = Join-Path $env:ProgramFiles 'AarshRemote'
$data    = Join-Path $env:ProgramData  'AarshRemote'
$svc     = 'AarshRemoteAgent'

if (Get-Service $svc -ErrorAction SilentlyContinue) {
  Write-Host "Stopping existing service…"; Stop-Service $svc -Force; Start-Sleep 2
}
New-Item -ItemType Directory -Force -Path $install, $data | Out-Null
Copy-Item -Path (Join-Path $Source '*') -Destination $install -Recurse -Force
$exe = Join-Path $install $exeName

if (-not $SkipPairing) {
  Write-Host "`nPairing this PC with $Server …`n"
  & $exe pair --server $Server --name $Name
  if ($LASTEXITCODE -ne 0) { throw "Pairing did not complete (exit $LASTEXITCODE). Fix the problem and re-run." }
}

if (-not (Get-Service $svc -ErrorAction SilentlyContinue)) {
  New-Service -Name $svc -BinaryPathName "`"$exe`" run" -DisplayName 'Aarsh Remote Agent' `
    -Description 'Connects this PC to your Aarsh Remote control server (outbound only). Remove with uninstall-agent.ps1.' `
    -StartupType Automatic | Out-Null
}
sc.exe config $svc start= delayed-auto | Out-Null
# Restart automatically: after 5 s, 5 s, then 30 s; reset the failure counter after a day.
sc.exe failure $svc reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null
Start-Service $svc
Write-Host "`nService '$svc' started. Logs: $data\Logs   Emergency disable: create $install\disable_remote_access.flag"

<#
.SYNOPSIS  Removes the Aarsh Remote agent service and program files (elevated PowerShell).
.PARAMETER RemoveData  Also delete C:\ProgramData\AarshRemote (device identity, config, logs). Without it, re-installing keeps the same identity.
#>
[CmdletBinding()] param([switch] $RemoveData)
$ErrorActionPreference = 'Stop'
$svc = 'AarshRemoteAgent'
if (Get-Service $svc -ErrorAction SilentlyContinue) {
  Stop-Service $svc -Force -ErrorAction SilentlyContinue
  sc.exe delete $svc | Out-Null
}
Remove-Item -Recurse -Force (Join-Path $env:ProgramFiles 'AarshRemote') -ErrorAction SilentlyContinue
if ($RemoveData) { Remove-Item -Recurse -Force (Join-Path $env:ProgramData 'AarshRemote') -ErrorAction SilentlyContinue }
Write-Host "Removed. Remember to revoke this device in the Aarsh Remote app so the server forgets it."

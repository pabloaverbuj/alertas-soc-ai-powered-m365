<#
.SYNOPSIS
  Puente local: trae las alertas SOC normalizadas que produjo el runbook (Azure Automation) y las
  deja en agents-soc/inbox/ para que soc-casemanager abra casos.
.DESCRIPTION
  El runbook 'Invoke-GeonosisSocAi' persiste las señales accionables normalizadas en la Automation
  Variable 'GeonosisSocAi-SocAlerts' (módulo F-Engine/Export-SocAlerts.psm1). Este script la lee con
  Get-AzAutomationVariable, deduplica por alertId contra los casos ya abiertos y el inbox, y escribe
  un .json por alerta nueva en agents-soc/inbox/.

  No abre casos ni remedia: solo materializa el inbox. La cadena de agentes la arranca soc-casemanager.
.PARAMETER ResourceGroup
  RG del Automation Account (default 'siem').
.PARAMETER AutomationAccount
  Automation Account del runbook (default 'aa-geonosis-soc-ai').
.PARAMETER VariableName
  Variable que contiene el array de alertas (default 'GeonosisSocAi-SocAlerts').
.PARAMETER WhatIf
  Muestra qué se ingeriría sin escribir el inbox.
.EXAMPLE
  ./Import-SocAlerts.ps1
  ./Import-SocAlerts.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $ResourceGroup     = 'siem',
    [string] $AutomationAccount = 'aa-geonosis-soc-ai',
    [string] $VariableName      = 'GeonosisSocAi-SocAlerts'
)

$ErrorActionPreference = 'Stop'
$root    = Split-Path $PSScriptRoot -Parent          # agents-soc/
$inbox   = Join-Path $root 'inbox'
$casesDir= Join-Path $root 'cases'
New-Item -ItemType Directory -Path $inbox -Force | Out-Null

# --- Auth Azure (interactivo si hace falta) ---------------------------------
if (-not (Get-Module -ListAvailable Az.Automation)) {
    throw "Falta el módulo Az.Automation. Instalá: Install-Module Az.Automation -Scope CurrentUser"
}
$ctx = Get-AzContext -ErrorAction SilentlyContinue
if (-not $ctx) {
    Write-Host "No hay sesión Azure. Abriendo login interactivo..." -ForegroundColor Yellow
    Connect-AzAccount | Out-Null
}

# --- Leer la variable del runbook -------------------------------------------
$var = Get-AzAutomationVariable -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccount `
        -Name $VariableName -ErrorAction Stop
$raw = $var.Value
if ([string]::IsNullOrWhiteSpace($raw)) {
    Write-Host "La variable '$VariableName' está vacía: el runbook aún no exportó alertas (o no hubo señales)." -ForegroundColor Yellow
    return
}
try { $alerts = @($raw | ConvertFrom-Json) } catch { throw "No pude parsear '$VariableName' como JSON: $($_.Exception.Message)" }
if (-not $alerts.Count) { Write-Host "Sin alertas en la variable." -ForegroundColor Yellow; return }

# --- alertId ya ingeridos: casos abiertos + inbox pendiente -----------------
$seen = [System.Collections.Generic.HashSet[string]]::new()
Get-ChildItem $casesDir -Recurse -Filter 'case.json' -ErrorAction SilentlyContinue | ForEach-Object {
    try { $aid = (Get-Content $_.FullName -Raw | ConvertFrom-Json).alert.alertId; if ($aid) { [void]$seen.Add($aid) } } catch {}
}
Get-ChildItem $inbox -Filter '*.json' -ErrorAction SilentlyContinue | ForEach-Object {
    try { $aid = (Get-Content $_.FullName -Raw | ConvertFrom-Json).alertId; if ($aid) { [void]$seen.Add($aid) } } catch {}
}

# --- Materializar inbox -----------------------------------------------------
$new = 0; $skip = 0
foreach ($a in $alerts) {
    if (-not $a.alertId) { continue }
    if ($seen.Contains($a.alertId)) { $skip++; continue }
    $safe = ($a.alertId -replace '[^A-Za-z0-9._-]', '_')
    $file = Join-Path $inbox "$safe.json"
    if ($PSCmdlet.ShouldProcess($file, "escribir alerta '$($a.alertId)'")) {
        $a | ConvertTo-Json -Depth 8 | Set-Content -Path $file -Encoding UTF8
    }
    Write-Host ("  + {0,-8} {1,-28} {2}" -f $a.severity.ToUpper(), $a.category, $a.title)
    $new++
}

Write-Host ""
Write-Host "Inbox: $new alerta(s) nueva(s), $skip ya ingerida(s)." -ForegroundColor Green
if ($new -gt 0) {
    Write-Host "Siguiente: en Claude Code, pedí 'procesá el inbox SOC' o invocá el agente soc-casemanager." -ForegroundColor Cyan
}

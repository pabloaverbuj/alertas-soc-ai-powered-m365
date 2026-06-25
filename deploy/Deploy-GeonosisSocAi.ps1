<#
.SYNOPSIS
  M17 — Provisioning de "Geonosis SOC AI powered" en Azure Automation (cero infra local).
.DESCRIPTION
  Crea/usa una Automation Account con Managed Identity, asigna permisos, sube variables seguras,
  importa los módulos y registra los schedules (semanal + critical). Idempotente donde se puede.
  Ejecutar UNA vez con un usuario con permisos de Owner/Privileged Role Admin sobre la sub/tenant.
.NOTES
  Copiá config/settings.example.json a config/settings.json y completá los valores de tu tenant.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $SubscriptionId,
    [Parameter(Mandatory)][string] $ResourceGroup,
    [string] $AutomationAccount= 'aa-soc-ai',
    [string] $Location         = 'brazilsouth',
    [string] $MaesterResourceGroup,
    [string] $MaesterAutomationAccount,
    [switch] $SkipGraph        # omití el paso 3 (app roles) si lo corrés aparte con Grant-GraphRoles.ps1
)
$ErrorActionPreference = 'Stop'
Connect-AzAccount | Out-Null
Set-AzContext -Subscription $SubscriptionId | Out-Null

# 1) Automation Account con System-Assigned Managed Identity
$aa = Get-AzAutomationAccount -ResourceGroupName $ResourceGroup -Name $AutomationAccount -ErrorAction SilentlyContinue
if (-not $aa) {
    $aa = New-AzAutomationAccount -ResourceGroupName $ResourceGroup -Name $AutomationAccount -Location $Location -AssignSystemIdentity
}
$miObjectId = (Get-AzAutomationAccount -ResourceGroupName $ResourceGroup -Name $AutomationAccount).Identity.PrincipalId
Write-Host "Managed Identity objectId: $miObjectId"

# 2) Permisos ARM (Sentinel / Log Analytics) sobre el RG del workspace
foreach ($role in 'Microsoft Sentinel Reader','Log Analytics Reader') {
    New-AzRoleAssignment -ObjectId $miObjectId -RoleDefinitionName $role `
        -Scope "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" -ErrorAction SilentlyContinue
}

# 3) Permisos Microsoft Graph + Defender (app roles a la MI).
#    OJO: Microsoft.Graph y Az NO conviven en la misma sesión (conflicto de assemblies, sobre todo en
#    Windows PowerShell 5.1). Por eso este paso va APARTE: corré deploy/Grant-GraphRoles.ps1 en una
#    sesión NUEVA y limpia (idealmente pwsh 7). Acá solo se imprime el recordatorio.
if ($SkipGraph) {
    Write-Host "[3] -SkipGraph: app roles se asignan con Grant-GraphRoles.ps1 (sesión Graph aparte)."
} else {
    Write-Host "[3] App roles (Graph/Defender): correr en sesión LIMPIA ->"
    Write-Host "    pwsh -NoProfile -File `"$PSScriptRoot\Grant-GraphRoles.ps1`" -MiObjectId $miObjectId"
    Write-Host "    (no se ejecuta acá para evitar el conflicto de assemblies Az+Graph)."
}

# 4) Variables: secretos + config (settings/crown-jewels van como variables porque Automation no monta tu carpeta)
function Set-Var($n,$v,$enc=$true){
    $ex = Get-AzAutomationVariable -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccount -Name $n -ErrorAction SilentlyContinue
    if ($ex) { Set-AzAutomationVariable -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccount -Name $n -Value $v -Encrypted:$enc | Out-Null }
    else     { New-AzAutomationVariable -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccount -Name $n -Value $v -Encrypted:$enc | Out-Null }
}
Set-Var 'GeonosisSocAi-AnthropicKey' 'TODO-anthropic-api-key'    # opción C: dejar TODO; la capa IA degrada sola
# Teams webhook: puede reutilizar una variable de Maester si pasás sus datos, o dejar TODO y cargarla manualmente.
$maesterHook = $null
if ($MaesterResourceGroup -and $MaesterAutomationAccount) {
    $maesterHook = (Get-AzAutomationVariable -ResourceGroupName $MaesterResourceGroup -AutomationAccountName $MaesterAutomationAccount -Name 'MaesterTeamsWebhook' -ErrorAction SilentlyContinue).Value
}
if ($maesterHook) { Set-Var 'GeonosisSocAi-TeamsWebhook' $maesterHook; Write-Host "Teams webhook copiado desde Maester." }
else { Set-Var 'GeonosisSocAi-TeamsWebhook' 'TODO-teams-webhook-url'; Write-Warning "Cargá la URL manual en GeonosisSocAi-TeamsWebhook." }
Set-Var 'GeonosisSocAi-AbuseChKey'   'TODO-abusech-auth-key'     # ThreatFox Auth-Key (abuse.ch); opcional, sin esto M12 omite IOCs
# Config no-secreta como variable (la leen los módulos cuando no hay filesystem):
Set-Var 'GeonosisSocAi-Settings'    (Get-Content (Join-Path $PSScriptRoot '..\config\settings.json')     -Raw) $false
Set-Var 'GeonosisSocAi-CrownJewels' (Get-Content (Join-Path $PSScriptRoot '..\config\crown-jewels.json') -Raw) $false
Set-Var 'GeonosisSocAi-LastState'   '' $false   # estado para el delta semana-a-semana (lo escribe el runbook)
Set-Var 'GeonosisSocAi-LastCriticalSig' '' $false   # firma de señales críticas para dedupe (no renotificar idéntico cada hora)
Set-Var 'GeonosisSocAi-Tickets'         '' $false   # tickets SOC (#9): estado/owner/due persistente + evidencia
Set-Var 'GeonosisSocAi-SocAlerts'       '' $false   # puente a agentes interactivos: alertas normalizadas (las lee agents-soc/ingest/Import-SocAlerts.ps1)
Set-Var 'GeonosisSocAi-LogoB64'     (Get-Content (Join-Path $PSScriptRoot '..\config\geologo.b64.txt') -Raw) $false   # isologo oficial (PNG base64) adjunto inline en el mail
# NOTA: Mail.Send permite enviar como buzones del tenant. Definí from/to en config/settings.json.

# 5) Construir runbook combinado (módulos inline + orquestador) e importarlo.
#    Automation no monta src/modules; se concatena todo en un único .ps1 PowerShell 7.2.
$srcRoot  = Join-Path $PSScriptRoot '..\src'
$combined = Join-Path ([System.IO.Path]::GetTempPath()) 'Invoke-GeonosisSocAi.Combined.ps1'
$sb = [System.Text.StringBuilder]::new()
[void]$sb.AppendLine('# GENERADO por Deploy-GeonosisSocAi.ps1 — NO editar a mano.')
[void]$sb.AppendLine("param([ValidateSet('weekly','critical')][string]`$Mode='weekly')")
[void]$sb.AppendLine("`$ErrorActionPreference='Stop'")
Get-ChildItem (Join-Path $srcRoot 'modules') -Recurse -Filter *.psm1 | Sort-Object FullName | ForEach-Object {
    $code = Get-Content $_.FullName -Raw
    # Export-ModuleMember no es válido fuera de un módulo: quitarlo (incluye continuación multilínea).
    $code = [regex]::Replace($code, '(?m)^\s*Export-ModuleMember[^\r\n]*(\r?\n\s+[^\r\n]*)*', '')
    [void]$sb.AppendLine("# ===== $($_.Name) =====")
    [void]$sb.AppendLine($code)
}
# Cuerpo del orquestador desde '# --- base' (saltea su param + el Import-Module de carpeta local).
$orch = Get-Content (Join-Path $srcRoot 'Invoke-GeonosisSocAi.ps1') -Raw
$idx  = $orch.IndexOf('# --- base')
if ($idx -lt 0) { throw "No encontré '# --- base' en el orquestador." }
[void]$sb.AppendLine($orch.Substring($idx))
Set-Content -Path $combined -Value $sb.ToString() -Encoding UTF8
Import-AzAutomationRunbook -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccount `
    -Name 'Invoke-GeonosisSocAi' -Type PowerShell72 -Path $combined -Published -Force | Out-Null
Write-Host "Runbook 'Invoke-GeonosisSocAi' importado y publicado (PowerShell 7.2)."

# 6) Schedules + registro al runbook con parámetro -Mode
#    Semanal: lunes 10:00 ART
New-AzAutomationSchedule -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccount `
    -Name 'GeonosisSocAi-Weekly' -StartTime (Get-Date '13:00').AddDays(1) -WeekInterval 1 -DaysOfWeek Monday `
    -TimeZone 'America/Argentina/Buenos_Aires' -ErrorAction SilentlyContinue | Out-Null
#    Critical: cada 1h (corre liviano y solo notifica ante señal crítica, M2)
New-AzAutomationSchedule -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccount `
    -Name 'GeonosisSocAi-Critical' -StartTime (Get-Date).AddHours(1) -HourInterval 1 -ErrorAction SilentlyContinue | Out-Null

Register-AzAutomationScheduledRunbook -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccount `
    -RunbookName 'Invoke-GeonosisSocAi' -ScheduleName 'GeonosisSocAi-Weekly'   -Parameters @{ Mode = 'weekly' }   -ErrorAction SilentlyContinue | Out-Null
Register-AzAutomationScheduledRunbook -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccount `
    -RunbookName 'Invoke-GeonosisSocAi' -ScheduleName 'GeonosisSocAi-Critical' -Parameters @{ Mode = 'critical' } -ErrorAction SilentlyContinue | Out-Null

Write-Host ""
Write-Host "== Deploy completo =="
Write-Host "App roles: asignados via Grant-GraphRoles.ps1 y EFECTIVOS (MI = sin admin-consent). Verificar en Entra (filtro Managed Identities) si querés."
Write-Host "Teams webhook: definir en GeonosisSocAi-TeamsWebhook si quedó en TODO."
Write-Host "Probar ahora: Start-AzAutomationRunbook -ResourceGroupName 'siem' -AutomationAccountName 'aa-geonosis-soc-ai' -Name 'Invoke-GeonosisSocAi' -Parameters @{Mode='weekly'} -Wait"

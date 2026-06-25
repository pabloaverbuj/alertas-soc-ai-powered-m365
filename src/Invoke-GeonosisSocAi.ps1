<#
.SYNOPSIS
  Geonosis SOC AI powered — entrypoint del runbook (Azure Automation).
.DESCRIPTION
  Orquesta el flujo en orden A→E:
    base → recolecta B (detección), C (observabilidad), D (threat intel), E (higiene)
         → ensambla y entrega el reporte (A) a Teams + email.
  Modo 'weekly' = reporte completo. Modo 'critical' = disparo out-of-band (M2): corre liviano y
  solo notifica si hay señal crítica (incidente high/critical, usuario high-risk, attack path a
  crown jewel, device-code sin bloqueo, config drift high).
.PARAMETER Mode
  weekly | critical
#>
[CmdletBinding()]
param(
    [ValidateSet('weekly','critical')] [string] $Mode = 'weekly'
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
Get-ChildItem "$root/modules" -Recurse -Filter *.psm1 | ForEach-Object { Import-Module $_.FullName -Force }

# --- base --------------------------------------------------------------------
$ctx      = Connect-SocContext
$settings = $ctx.Settings
$days     = $settings.schedule.lookbackDaysWeekly
Write-Output "== Geonosis SOC AI ($Mode) =="

# --- B. Detección ------------------------------------------------------------
$incDeep = if ($null -ne $settings.incidents.deepFetchAlerts) { [bool]$settings.incidents.deepFetchAlerts } else { $true }
$incMax  = if ($settings.incidents.maxAlertsPerIncident) { [int]$settings.incidents.maxAlertsPerIncident } else { 8 }
$incidents = Get-SocIncidents  -LookbackDays $days -CriticalSeverities $settings.thresholds.criticalSeverities `
                -DeepFetch $incDeep -MaxAlertsPerIncident $incMax
$coverage  = Get-SocCoverage   -Settings $settings

# --- C. Observabilidad -------------------------------------------------------
$identity  = Get-IdentityRisk     -LookbackDays $days
$endpoints = Get-EndpointPosture
$behavior  = Get-BehaviorAnomalies -LookbackDays $days
$paths     = Get-AttackPaths       -Settings $settings
$signins   = Get-SignInTelemetry   -LookbackDays $days
$spray     = Get-PasswordSpray     -LookbackDays $days `
                -SprayUserThreshold ([int]($settings.spray.userThreshold | ForEach-Object { if ($_) { $_ } else { 5 } })) `
                -TrustedEgressIps @($settings.spray.trustedEgressIps)

# --- Advanced Hunting (#1/#3/#4) -------------------------------------------
$ahEmail   = Get-EmailPhishingRisk     -LookbackDays $days
$ahUrl     = Get-UrlClickRisk          -LookbackDays $days
$ahOauth   = Get-OAuthAppRisk          -LookbackDays $days -IgnoreAppPatterns @($settings.oauthHunting.ignoreAppPatterns)
$ahPriv    = Get-PrivilegedUserActivity -LookbackDays $days

# --- D. Threat Intel ---------------------------------------------------------
$trends     = Get-ThreatTrends
$deviceCode = Get-DeviceCodePhishing -LookbackDays $days
$trendCov   = Compare-TrendCoverage -Trends $trends -Coverage $coverage -DeviceCode $deviceCode

# --- E. Higiene --------------------------------------------------------------
$hygiene = Get-DataHygiene
$drift   = Get-ConfigDrift

# --- Disparo out-of-band (M2): evaluar señales críticas ----------------------
$critical = @(
    @($incidents.Critical).Count -gt 0
    ($settings.thresholds.highRiskUserAlert -and @($identity.HighRiskUsers).Count -gt 0)
    ($settings.thresholds.newAttackPathAlert -and @($paths.ToCrown).Count -gt 0)
    ($settings.thresholds.deviceCodeAlert -and $deviceCode.AtRisk -and @($deviceCode.SignIns).Count -gt 0)
    @($drift.High).Count -gt 0
) -contains $true

# Firma de las señales críticas (para dedupe: no renotificar lo MISMO cada hora).
$critItems = @()
$critItems += @($incidents.Critical | ForEach-Object { "INC:$($_.Id)" })
$critItems += @($identity.HighRiskUsers | ForEach-Object { "HRU:$($_.userPrincipalName)" })
$critItems += @($paths.ToCrown | ForEach-Object { "AP:$($_.Id)" })
$critItems += @($drift.High | ForEach-Object { "DRIFT:$($_.Policy)" })
if ($deviceCode.AtRisk) { $critItems += 'DEVICECODE:atRisk' }
$critSig = (($critItems | Where-Object { $_ } | Sort-Object) -join '|')
$prevSig = Get-SocSecret -Name 'GeonosisSocAi-LastCriticalSig'

# --- Puente a agentes SOC interactivos: normalizar señales -> 'GeonosisSocAi-SocAlerts' --------
# Se persiste SIEMPRE (antes del dedup de notificación) para que el bridge local
# (agents-soc/ingest/Import-SocAlerts.ps1) tenga las alertas accionables actuales.
try {
    $socAlerts = Export-SocAlerts -Incidents $incidents -Identity $identity -AttackPaths $paths `
        -Drift $drift -DeviceCode $deviceCode -PasswordSpray $spray `
        -Hunting ([pscustomobject]@{ OAuthApps=$ahOauth; UrlClicks=$ahUrl }) -LookbackDays $days
    Set-SocState -Name 'GeonosisSocAi-SocAlerts' -Value (@($socAlerts) | ConvertTo-Json -Depth 8 -Compress)
    Write-Output "Puente SOC: $(@($socAlerts).Count) alertas normalizadas -> GeonosisSocAi-SocAlerts."
} catch { Write-Warning "[socalerts] no se pudo exportar el puente: $($_.Exception.Message)" }

if ($Mode -eq 'critical') {
    if (-not $critical) {
        Write-Output "Sin señales críticas — no se notifica (modo critical)."
        return
    }
    if ($critSig -eq $prevSig) {
        Write-Output "Señal crítica SIN CAMBIOS vs la última notificación — no se renotifica (dedupe)."
        return
    }
    Write-Output "Señal crítica NUEVA/cambiada — se notifica."
}

# --- A. Informe: ensamblar y publicar ---------------------------------------
# crown jewels (para que la IA reconozca identidades privilegiadas en la correlación)
$cjRaw = Get-SocSecret -Name 'GeonosisSocAi-CrownJewels'
$crownJewels = if ($cjRaw) { try { $cjRaw | ConvertFrom-Json } catch { $null } } else { $null }

$data = [ordered]@{
    Incidents     = $incidents
    Coverage      = $coverage
    Identity      = $identity
    Endpoints     = $endpoints
    Behavior      = $behavior
    AttackPaths   = $paths
    SignIns       = $signins
    PasswordSpray = $spray
    Trends        = $trends
    DeviceCode    = $deviceCode
    TrendCoverage = $trendCov
    Hygiene       = $hygiene
    Drift         = $drift
    CrownJewels   = $crownJewels
    Hunting       = [pscustomobject]@{ EmailPhishing=$ahEmail; UrlClicks=$ahUrl; OAuthApps=$ahOauth; PrivActivity=$ahPriv }
}

# estado del reporte anterior (para "qué cambió")
$prevRaw   = Get-SocSecret -Name 'GeonosisSocAi-LastState'
$prevState = if ($prevRaw) { try { $prevRaw | ConvertFrom-Json } catch { $null } } else { $null }

# Postura (#8): Secure Score + Exposure con delta vs previo.
try { $data.Posture = Get-SocPostureScore -PrevState $prevState }
catch { Write-Warning "[posture] fallo: $($_.Exception.Message) @ $($_.InvocationInfo.PositionMessage)"; $data.Posture = $null }
# Motor de riesgo (#2): estado por hallazgo + score por entidad (usa todo $data + estado previo).
try { $data.RiskEngine = Get-SocRiskEngine -Data $data -PrevState $prevState }
catch { Write-Warning "[riskengine] fallo: $($_.Exception.Message) :: STACK $($_.ScriptStackTrace)"; $data.RiskEngine = $null }

$report = New-SocReport -Mode $Mode -Data $data -Settings $settings -PeriodDays $days -PrevState $prevState
Publish-SocReport -Report $report -Settings $settings

# Tickets (#9): derivar de la remediación, conservar estado/owner/due, postear lista a Teams, persistir (evidencia).
$prevTkRaw = Get-SocSecret -Name 'GeonosisSocAi-Tickets'
$prevTk    = if ($prevTkRaw) { try { $prevTkRaw | ConvertFrom-Json } catch { @() } } else { @() }
$tickets   = Build-SocTickets -Report $report -PrevTickets $prevTk
if ($settings.delivery.teams.enabled) { Send-SocTeamsTickets -Tickets $tickets -Settings $settings }
Set-SocState -Name 'GeonosisSocAi-Tickets' -Value ($tickets | ConvertTo-Json -Depth 6 -Compress)

# guardar estado de esta corrida para el delta de la próxima
$state = [ordered]@{
    fecha              = (Get-Date).ToString('yyyy-MM-dd HH:mm')
    incidentesCriticos = @($incidents.Critical).Count
    usuariosAltoRiesgo = @($identity.HighRiskUsers).Count
    endpointsRiesgo    = @($endpoints.HighRisk).Count
    gapsCobertura      = @($coverage.Gaps).Count
    driftHigh          = @($drift.High).Count
    deviceCodeEnRiesgo = [bool]$deviceCode.AtRisk
    incidentes         = @($incidents.Items | Select-Object Id,Title,Severity,Status)
    findings           = @($data.RiskEngine.StateForSave)   # para el estado por hallazgo del motor de riesgo
    securePct          = $data.Posture.Secure.Pct           # para delta de Secure Score
    exposure           = $data.Posture.Exposure             # para delta de Exposure Score
}
Set-SocState -Name 'GeonosisSocAi-LastState' -Value ($state | ConvertTo-Json -Depth 6 -Compress)
# guardar firma crítica para dedupe (evita renotificar lo mismo cada hora en modo critical)
Set-SocState -Name 'GeonosisSocAi-LastCriticalSig' -Value $critSig
Write-Output "== Reporte $Mode publicado =="

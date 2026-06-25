# C-Observability/Get-BehaviorAnomalies.psm1
# M9 — Comportamiento (UEBA). Requiere UEBA prendido en Sentinel (Settings > Entity behavior),
# si no las tablas BehaviorAnalytics/Anomalies están vacías. El módulo degrada con gracia.

function Get-BehaviorAnomalies {
    [CmdletBinding()]
    param([int] $LookbackDays = 7)

    $kql = @"
Anomalies
| where TimeGenerated >= ago(${LookbackDays}d)
| where Score >= 1.0
| project TimeGenerated, UserName, AnomalyTemplateName=RuleName, Score, Tactics, Description
| order by Score desc
| take 50
"@
    try {
        $rows = Invoke-SocKql -Query $kql -TimespanDays $LookbackDays
    } catch {
        Write-Warning "[ueba] Tabla Anomalies inaccesible (¿UEBA apagado?). $($_.Exception.Message)"
        $rows = @()
    }

    $ueba = if ($rows.Count -eq 0) { 'UEBA sin datos (verificar que esté habilitado)' } else { "$($rows.Count) anomalías de comportamiento" }
    return [pscustomobject]@{
        Summary   = "Comportamiento — $ueba"
        Anomalies = $rows
        Enabled   = ($rows.Count -gt 0)
    }
}

Export-ModuleMember -Function Get-BehaviorAnomalies

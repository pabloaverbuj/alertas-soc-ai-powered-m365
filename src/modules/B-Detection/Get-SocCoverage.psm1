# B-Detection/Get-SocCoverage.psm1
# M4 — Cobertura SOC optimization (threat-based) en VIVO vía API recommendations.
# M6 — Marca los gaps a cerrar (recomendaciones de cobertura en estado Active).
# Schema real (verificado 2026-06-18): recommendationTypeId 'Precision_Coverage' = cobertura por amenaza;
#   state Active = gap abierto, CompletedBySystem = cubierto. (No existe activeDetections/totalDetections.)

function Get-SocCoverage {
    [CmdletBinding()]
    param([object] $Settings = (Get-SocContext).Settings)

    $recs = Get-SocOptimizationRecommendations -Settings $Settings

    $coverage = $recs | Where-Object { $_.Type -like 'Precision_Coverage*' }
    $rows = $coverage | ForEach-Object {
        [pscustomobject]@{
            Scenario = $_.Scenario
            State    = $_.State
            Gap      = ($_.State -eq 'Active')   # Active = cobertura incompleta
        }
    }
    $gaps = $rows | Where-Object Gap   # M6: gaps prioritarios

    return [pscustomobject]@{
        Summary = New-CoverageSummary -Rows $rows -Gaps $gaps -All $recs
        Rows    = $rows
        Gaps    = $gaps
        Worst   = $gaps   # compat con consumidores previos
        All     = $recs
    }
}

function Get-SocOptimizationRecommendations {
    param([object] $Settings)
    # SOC optimization vía Microsoft.SecurityInsights/recommendations (ARM, preview 2024-01-01).
    $w    = $Settings.workspace
    $path = "/subscriptions/$($w.subscriptionId)/resourceGroups/$($w.resourceGroup)" +
            "/providers/Microsoft.OperationalInsights/workspaces/$($w.name)" +
            "/providers/Microsoft.SecurityInsights/recommendations"
    try {
        $recs = Invoke-SocArm -Path $path -ApiVersion '2024-01-01-preview'
        return $recs | ForEach-Object {
            [pscustomobject]@{
                Type     = $_.properties.recommendationTypeId
                State    = $_.properties.state
                Title    = $_.properties.title
                Scenario = ($_.properties.title -replace '^Coverage improvement against ', '')
            }
        }
    } catch {
        Write-Warning "[coverage] API SOC-opt no disponible. $($_.Exception.Message)"
        return @()
    }
}

function New-CoverageSummary {
    param($Rows, $Gaps, $All)
    if (-not @($All).Count) { return "Cobertura SOC-opt: sin datos (API no devolvio recomendaciones)." }
    $byState  = $All | Group-Object State | ForEach-Object { "$($_.Name): $($_.Count)" }
    $gapLines = $Gaps | Sort-Object Scenario | ForEach-Object { "  - GAP: $($_.Scenario)" }
    @"
Cobertura SOC-opt: $(@($All).Count) recomendaciones [$($byState -join ' | ')]
Gaps de cobertura por amenaza (Active): $(@($Gaps).Count) de $(@($Rows).Count) escenarios
$($gapLines -join "`n")
"@
}

Export-ModuleMember -Function Get-SocCoverage

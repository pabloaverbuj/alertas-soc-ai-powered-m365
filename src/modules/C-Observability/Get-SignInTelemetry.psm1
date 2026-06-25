# C-Observability/Get-SignInTelemetry.psm1
# M11 — Inicios de sesión, uso de apps y locaciones. Base de comportamiento sobre SigninLogs
# (ya ingerido en el workspace Sentinel/Log Analytics). Resalta locaciones nuevas y picos de apps.

function Get-SignInTelemetry {
    [CmdletBinding()]
    param([int] $LookbackDays = 7)

    $rows = Invoke-SocKql -TimespanDays $LookbackDays -Query @"
SigninLogs
| where TimeGenerated >= ago(${LookbackDays}d)
| where ResultType == 0
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize SignIns = count(), Users = dcount(UserPrincipalName) by AppDisplayName, Country
| order by SignIns desc
"@

    # Locaciones nuevas vs ventana previa (señal de viaje imposible / acceso desde país nuevo)
    $newLoc = Invoke-SocKql -TimespanDays ($LookbackDays*4) -Query @"
SigninLogs
| where ResultType == 0
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize FirstSeen = min(TimeGenerated) by UserPrincipalName, Country
| where FirstSeen >= ago(${LookbackDays}d)
| project UserPrincipalName, Country, FirstSeen
"@

    $topApps      = $rows | Sort-Object SignIns -Descending | Select-Object -First 10
    $topCountries = $rows | Group-Object Country | Sort-Object Count -Descending | Select-Object -First 10

    return [pscustomobject]@{
        Summary      = "Sign-ins — top app: $(if($topApps){$topApps[0].AppDisplayName}else{'s/d'}) · países activos: $(@($topCountries).Count) · locaciones nuevas (usuario/país): $(@($newLoc).Count)"
        TopApps      = $topApps
        Countries    = $topCountries
        NewLocations = $newLoc
    }
}

Export-ModuleMember -Function Get-SignInTelemetry

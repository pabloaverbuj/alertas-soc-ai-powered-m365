# G-Hunting/Get-UrlClickRisk.psm1
# #3 — Clicks a URLs maliciosas vía Advanced Hunting (UrlClickEvents, Safe Links). Usuarios que
# hicieron click (o pasaron la advertencia) sobre URLs con amenaza. Requiere Safe Links / Defender for Office.

function Get-UrlClickRisk {
    [CmdletBinding()]
    param([int] $LookbackDays = 7)
    $ok = $true; $rows = @()
    try {
        $rows = @(Invoke-SocHunting -Query @"
UrlClickEvents
| where Timestamp > ago(${LookbackDays}d)
| where IsClickedThrough == 1 or isnotempty(ThreatTypes)
| project Timestamp, AccountUpn, Url, ActionType, ThreatTypes, IsClickedThrough
| order by Timestamp desc
| take 50
"@)
    } catch { Write-Warning "[ah-url] UrlClickEvents no disponible. $($_.Exception.Message)"; $ok = $false }

    $through = @($rows | Where-Object { $_.IsClickedThrough -eq 1 }).Count
    return [pscustomobject]@{
        Available = $ok
        Rows      = $rows
        ClickedThrough = $through
        Summary   = if ($ok) { "Clicks a URLs con amenaza: $(@($rows).Count) · que pasaron la advertencia (clicked-through): $through" }
                    else      { "URL clicks — tabla UrlClickEvents no disponible (Safe Links / licencia)" }
    }
}
Export-ModuleMember -Function Get-UrlClickRisk

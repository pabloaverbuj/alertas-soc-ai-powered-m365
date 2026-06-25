# G-Hunting/Get-EmailPhishingRisk.psm1
# #3 — Email security vía Advanced Hunting (EmailEvents). Phishing/malware: entregados vs bloqueados,
# top destinatarios. Requiere Defender for Office onboarded en Defender XDR (tabla EmailEvents).

function Get-EmailPhishingRisk {
    [CmdletBinding()]
    param([int] $LookbackDays = 7)
    $ok = $true; $rows = @()
    try {
        $rows = @(Invoke-SocHunting -Query @"
EmailEvents
| where Timestamp > ago(${LookbackDays}d)
| where ThreatTypes has_any ('Phish','Malware')
| summarize Emails=count(), Entregados=countif(DeliveryAction == 'Delivered'), Ultimo=max(Timestamp)
          by RecipientEmailAddress, ThreatTypes
| order by Emails desc
| take 50
"@)
    } catch { Write-Warning "[ah-email] EmailEvents no disponible. $($_.Exception.Message)"; $ok = $false }

    $entregados = (@($rows) | Measure-Object -Property Entregados -Sum).Sum
    return [pscustomobject]@{
        Available = $ok
        Rows      = $rows
        Delivered = [int]$entregados
        Summary   = if ($ok) { "Email phishing/malware — destinatarios afectados: $(@($rows).Count) · mensajes entregados (no bloqueados): $([int]$entregados)" }
                    else      { "Email phishing — tabla EmailEvents no disponible (Defender for Office / licencia)" }
    }
}
Export-ModuleMember -Function Get-EmailPhishingRisk

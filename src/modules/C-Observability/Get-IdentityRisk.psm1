# C-Observability/Get-IdentityRisk.psm1
# M7 — Identidad: risky users/sign-ins (Entra ID Protection P2), impossible travel, MFA gaps, legacy auth.

function Get-IdentityRisk {
    [CmdletBinding()]
    param([int] $LookbackDays = 7)

    # Risky users (ID Protection)
    $riskyUsers = Invoke-SocGraph -Path "/identityProtection/riskyUsers?`$filter=riskLevel eq 'high' or riskLevel eq 'medium'"
    # Risk detections (impossible travel, anonymized IP, unfamiliar sign-in, token issuer anomaly...)
    $since = (Get-Date).ToUniversalTime().AddDays(-$LookbackDays).ToString('o')
    $detections = Invoke-SocGraph -Path "/identityProtection/riskDetections?`$filter=detectedDateTime ge $since"

    $highRiskUsers = $riskyUsers | Where-Object riskLevel -eq 'high'
    $impossible    = $detections | Where-Object riskEventType -in @('impossibleTravel','unlikelyTravel','anomalousToken')

    return [pscustomobject]@{
        Summary       = New-IdentitySummary -Risky $riskyUsers -Detections $detections
        RiskyUsers    = $riskyUsers
        HighRiskUsers = $highRiskUsers      # alimenta disparo out-of-band (M2)
        Detections    = $detections
        Impossible    = $impossible
    }
}

function New-IdentitySummary {
    param($Risky, $Detections)
    $byType = $Detections | Group-Object riskEventType | Sort-Object Count -Descending |
              ForEach-Object { "$($_.Name): $($_.Count)" }
    @"
Identidad — usuarios en riesgo: $($Risky.Count) (high: $((@($Risky | Where-Object riskLevel -eq 'high')).Count))
Detecciones de riesgo ($($Detections.Count)): $($byType -join ' · ')
"@
}

Export-ModuleMember -Function Get-IdentityRisk

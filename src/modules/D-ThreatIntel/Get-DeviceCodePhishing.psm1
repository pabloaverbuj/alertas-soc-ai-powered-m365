# D-ThreatIntel/Get-DeviceCodePhishing.psm1
# M14 — Detección dedicada de device-code phishing (Kali365 PhaaS): roba tokens post-MFA.
# Dos señales: (1) sign-ins reales con deviceCode flow; (2) si la CA que lo bloquea está enforced.

function Get-DeviceCodePhishing {
    [CmdletBinding()]
    param([int] $LookbackDays = 7)

    # (1) Sign-ins con device code flow — casi nunca legítimos en endpoints de oficina.
    $signins = Invoke-SocKql -TimespanDays $LookbackDays -Query @"
SigninLogs
| where TimeGenerated >= ago(${LookbackDays}d)
| where AuthenticationProtocol == "deviceCode"
| extend Country = tostring(LocationDetails.countryOrRegion)
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, Country,
          ResultType, DeviceDetail
| order by TimeGenerated desc
"@

    # (2) ¿Está enforced la CA que bloquea device code flow? (hoy: GLOBAL-1020 en report-only)
    $blocked = Test-DeviceCodeBlocked

    return [pscustomobject]@{
        Summary  = "Device-code phishing (Kali365) — sign-ins deviceCode: $(@($signins).Count) · bloqueo CA enforced: $blocked"
        SignIns  = $signins
        Blocked  = $blocked
        AtRisk   = (-not $blocked)        # alimenta M2 y M13
    }
}

function Test-DeviceCodeBlocked {
    # Busca una CA habilitada (no report-only) que bloquee el authentication flow device code.
    try {
        $pols = Invoke-SocGraph -Path "/identity/conditionalAccess/policies"
        $match = $pols | Where-Object {
            $_.state -eq 'enabled' -and
            $_.grantControls.builtInControls -contains 'block' -and
            $_.conditions.authenticationFlows.transferMethods -match 'deviceCodeFlow'
        }
        return [bool]$match
    } catch {
        Write-Warning "[devicecode] No se pudo leer CA policies. $($_.Exception.Message)"
        return $null
    }
}

Export-ModuleMember -Function Get-DeviceCodePhishing

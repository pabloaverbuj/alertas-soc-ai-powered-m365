# D-ThreatIntel/Compare-TrendCoverage.psm1
# M13 — Cruce tendencia <-> cobertura: conecta lo que se usa afuera con TUS gaps reales.
# Mapea cada tendencia caliente a los escenarios de cobertura del tenant (match por nombre).
# Expuesto = existe un escenario relacionado con cobertura en estado Active (gap), o no hay cobertura.

function Compare-TrendCoverage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object] $Trends,     # Get-ThreatTrends
        [Parameter(Mandatory)][object] $Coverage,   # Get-SocCoverage (Rows con Scenario/State/Gap)
        [Parameter(Mandatory)][object] $DeviceCode  # Get-DeviceCodePhishing (M14)
    )

    # Mapeo tendencia -> regex contra el nombre del escenario de cobertura (Precision_Coverage).
    $map = @(
        @{ Trend='PhaaS / AiTM / device-code (Kali365, EvilProxy, Tycoon 2FA)'; Match='AiTM|Adversary in the Middle|Credential Harvest|Credential Exploitation|Okta'; Mitre='T1566, T1528, T1621' }
        @{ Trend='Ransomware operado por humanos';                              Match='Ransomware';                                                                Mitre='T1486, T1490, T1078' }
        @{ Trend='Fraude financiero ERP/SAP / BEC';                            Match='ERP|SAP|Financial|BEC';                                                    Mitre='T1565, T1114' }
    )

    $findings = foreach ($m in $map) {
        $hit     = $Coverage.Rows | Where-Object { $_.Scenario -match $m.Match }
        $gaps    = @($hit | Where-Object Gap)
        $exposed = if ($hit) { [bool]$gaps.Count } else { $true }
        [pscustomobject]@{
            Trend     = $m.Trend
            Scenarios = (($hit.Scenario) -join '; ')
            GapCount  = $gaps.Count
            Total     = @($hit).Count
            Exposed   = $exposed
            Mitre     = $m.Mitre
        }
    }
    $exposed = $findings | Where-Object Exposed

    return [pscustomobject]@{
        Summary  = New-TrendCoverageSummary -Findings $findings -DeviceCode $DeviceCode
        Findings = $findings
        Exposed  = $exposed
    }
}

function New-TrendCoverageSummary {
    param($Findings, $DeviceCode)
    $lines = $Findings | ForEach-Object {
        $flag = if ($_.Exposed) { '[EXPUESTO]' } else { '[ok]' }
        $cov  = if ($_.Total) { "gaps $($_.GapCount)/$($_.Total): $($_.Scenarios)" } else { 'sin escenario de cobertura' }
        "  - $($_.Trend) -> $cov $flag"
    }
    $dc = if ($DeviceCode.AtRisk) { '[!] device-code phishing SIN bloqueo enforced (CA en report-only)' } else { 'device-code flow bloqueado' }
    @"
Cruce tendencia <-> cobertura:
$($lines -join "`n")
Kali365 / device-code: $dc
"@
}

Export-ModuleMember -Function Compare-TrendCoverage

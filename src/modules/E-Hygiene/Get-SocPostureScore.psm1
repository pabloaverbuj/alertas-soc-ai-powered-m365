# E-Hygiene/Get-SocPostureScore.psm1
# M15b — Métricas de madurez: Microsoft Secure Score (Graph) + Exposure Score (Defender),
# con delta vs el reporte anterior. Secure Score: mayor = mejor. Exposure: menor = mejor.

function Get-SocPostureScore {
    [CmdletBinding()]
    param([object] $PrevState = $null)

    # Secure Score (Graph) — requiere SecurityEvents.Read.All
    $secure = $null
    try {
        $ss = Invoke-SocGraph -Path "/security/secureScores?`$top=1"
        $s0 = @($ss)[0]
        if ($s0 -and $s0.maxScore) {
            $secure = [pscustomobject]@{
                Current = [math]::Round([double]$s0.currentScore,1)
                Max     = [math]::Round([double]$s0.maxScore,1)
                Pct     = [math]::Round(100 * [double]$s0.currentScore / [double]$s0.maxScore,1)
                Date    = $s0.createdDateTime
            }
        }
    } catch { Write-Warning "[posture] Secure Score no disponible. $($_.Exception.Message)" }

    # Exposure Score (Defender) — best-effort
    $exposure = $null
    try {
        $tok = Get-SocToken -ResourceUrl 'https://api.securitycenter.microsoft.com'
        $ex  = Invoke-RestMethod -Uri 'https://api.securitycenter.microsoft.com/api/exposureScore' -Headers @{ Authorization = "Bearer $tok" }
        if ($null -ne $ex.score) { $exposure = [math]::Round([double]$ex.score,1) }
    } catch { Write-Warning "[posture] Exposure score no disponible. $($_.Exception.Message)" }

    # delta vs previo
    $prevSecure = $null; $prevExp = $null
    if ($PrevState) { $prevSecure = $PrevState.securePct; $prevExp = $PrevState.exposure }
    $secureDelta = if ($secure -and $null -ne $prevSecure) { [math]::Round($secure.Pct - [double]$prevSecure,1) } else { $null }
    $expDelta    = if ($null -ne $exposure -and $null -ne $prevExp) { [math]::Round($exposure - [double]$prevExp,1) } else { $null }

    $sTxt = if ($secure) { "$($secure.Pct)% ($($secure.Current)/$($secure.Max))$(if($null -ne $secureDelta){" Δ $(if($secureDelta -ge 0){'+'})$secureDelta pp"})" } else { 's/d' }
    $eTxt = if ($null -ne $exposure) { "$exposure$(if($null -ne $expDelta){" Δ $(if($expDelta -ge 0){'+'})$expDelta"})" } else { 's/d' }

    return [pscustomobject]@{
        Summary       = "Secure Score: $sTxt · Exposure Score: $eTxt"
        Secure        = $secure
        SecureDelta   = $secureDelta
        Exposure      = $exposure
        ExposureDelta = $expDelta
    }
}

Export-ModuleMember -Function Get-SocPostureScore

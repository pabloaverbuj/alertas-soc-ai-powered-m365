# E-Hygiene/Get-ConfigDrift.psm1
# M16 — Detección de config drift de seguridad. Caza el tipo de hallazgo que ya encontramos a mano:
# políticas de Conditional Access en report-only que deberían estar enforced, exclusiones amplias,
# y controles clave apagados (token protection, phishing-resistant MFA).

function Get-ConfigDrift {
    [CmdletBinding()]
    param()
    $pols = Invoke-SocGraph -Path "/identity/conditionalAccess/policies"

    $findings = New-Object System.Collections.Generic.List[object]

    foreach ($p in $pols) {
        # Report-only que bloquea / exige MFA (debería estar enforced)
        if ($p.state -eq 'enabledForReportingButNotEnforced' -and
            ($p.grantControls.builtInControls -match 'block|mfa' -or
             $p.conditions.authenticationFlows.transferMethods -match 'deviceCodeFlow')) {
            $findings.Add([pscustomobject]@{
                Severity = 'high'; Type = 'CA report-only'; Policy = $p.displayName
                Detail = 'Política de control diseñada pero NO enforced (report-only).'
            })
        }
        # Token protection disabled
        if ($p.displayName -match 'token protection' -and $p.state -eq 'disabled') {
            $findings.Add([pscustomobject]@{ Severity='medium'; Type='Token protection off'; Policy=$p.displayName; Detail='Anti robo de token de sesión deshabilitado.' })
        }
        # Exclusiones grandes en políticas enforced
        $exCount = @($p.conditions.users.excludeUsers).Count + @($p.conditions.users.excludeGroups).Count
        if ($p.state -eq 'enabled' -and $exCount -ge 8) {
            $findings.Add([pscustomobject]@{ Severity='medium'; Type='Exclusión amplia'; Policy=$p.displayName; Detail="$exCount usuarios/grupos excluidos." })
        }
    }

    $arr = $findings.ToArray()   # array (NO List): @() sobre List[object] tira "Argument types do not match" en pwsh
    return [pscustomobject]@{
        Summary  = "Config drift — hallazgos: $($arr.Count) (high: $(@($arr | Where-Object Severity -eq 'high').Count))"
        Findings = $arr
        High     = @($arr | Where-Object Severity -eq 'high')   # alimenta M2
    }
}

Export-ModuleMember -Function Get-ConfigDrift

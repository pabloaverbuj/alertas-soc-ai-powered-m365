# C-Observability/Get-AttackPaths.psm1
# M10 — Rutas de ataque hacia activos críticos.
# Vía Azure Resource Graph (Defender for Cloud attack paths): securityresources type microsoft.security/attackpaths.
# (Geonosis sin IaaS/Defender for Cloud -> normalmente 0; degrada limpio, sin 400.)

function Get-AttackPaths {
    [CmdletBinding()]
    param(
        [object] $Settings = (Get-SocContext).Settings,
        [string] $CrownJewelsPath = "$PSScriptRoot/../../../config/crown-jewels.json"
    )
    # Local: archivo. En Azure Automation: Automation Variable 'GeonosisSocAi-CrownJewels'.
    $hasCj  = $CrownJewelsPath -and [System.IO.File]::Exists($CrownJewelsPath)
    $cjJson = if ($hasCj) { Get-Content -LiteralPath $CrownJewelsPath -Raw } else { Get-SocSecret -Name 'GeonosisSocAi-CrownJewels' }
    $crown  = if ($cjJson) { $cjJson | ConvertFrom-Json } else { [pscustomobject]@{} }

    $sub   = $Settings.workspace.subscriptionId
    $query = "securityresources | where type=='microsoft.security/attackpaths' " +
             "| project name, displayName=tostring(properties.displayName), " +
             "potentialImpact=tostring(properties.potentialImpact), risk=tostring(properties.riskCategories)"
    try {
        $resp  = Invoke-SocArm -Method POST -Path "/providers/Microsoft.ResourceGraph/resources" `
                    -ApiVersion '2021-03-01' -Body @{ subscriptions = @($sub); query = $query }
        $paths = @($resp.data)
    } catch {
        Write-Warning "[attackpaths] ARG no disponible. $($_.Exception.Message)"
        $paths = @()
    }

    $enriched = foreach ($p in $paths) {
        $hit = Test-CrownJewelTarget -Text "$($p.displayName) $($p.potentialImpact)" -Crown $crown
        [pscustomobject]@{
            Id         = $p.name
            Name       = $p.displayName
            Impact     = $p.potentialImpact
            Risk       = $p.risk
            TargetTier = $hit.Tier
            ToCrown    = $hit.Match
        }
    }
    $toCrown = $enriched | Where-Object ToCrown | Sort-Object TargetTier

    return [pscustomobject]@{
        Summary = "Rutas de ataque (ARG/Defender for Cloud): $(@($enriched).Count) total | hacia crown jewels: $(@($toCrown).Count)"
        Paths   = $enriched
        ToCrown = $toCrown          # alimenta disparo out-of-band (M2)
    }
}

function Test-CrownJewelTarget {
    param([string] $Text, $Crown)
    foreach ($bucket in @('identities','groups','devices','cloudResources')) {
        foreach ($cj in $Crown.$bucket) {
            if ($cj.value -and $Text -like "*$($cj.value)*") {
                return [pscustomobject]@{ Match = $true; Tier = $cj.tier }
            }
        }
    }
    return [pscustomobject]@{ Match = $false; Tier = 99 }
}

Export-ModuleMember -Function Get-AttackPaths

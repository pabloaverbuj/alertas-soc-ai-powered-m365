# G-Hunting/Get-OAuthAppRisk.psm1
# #4 — Apps OAuth: consents recientes (posible illicit consent grant). Vía Graph directoryAudits.
# Requiere AuditLog.Read.All.

function Get-OAuthAppRisk {
    [CmdletBinding()]
    param([int] $LookbackDays = 7, [string[]] $IgnoreAppPatterns = @())
    $ok = $true; $rows = @()
    $since = (Get-Date).ToUniversalTime().AddDays(-$LookbackDays).ToString('o')
    try {
        $filter = "activityDateTime ge $since and (activityDisplayName eq 'Consent to application' or activityDisplayName eq 'Add app role assignment grant to user' or activityDisplayName eq 'Add delegated permission grant')"
        $aud = Invoke-SocGraph -Path "/auditLogs/directoryAudits?`$filter=$([uri]::EscapeDataString($filter))&`$top=50"
        $rows = @($aud | ForEach-Object {
            [pscustomobject]@{
                Fecha   = $_.activityDateTime
                Accion  = $_.activityDisplayName
                App     = (@($_.targetResources | ForEach-Object { $_.displayName }) -join ', ')
                Quien   = $_.initiatedBy.user.userPrincipalName
                Result  = $_.result
            }
        })
    } catch { Write-Warning "[ah-oauth] directoryAudits no disponible (AuditLog.Read.All?). $($_.Exception.Message)"; $ok = $false }

    # Flagged = consents que valen una alerta: apps de TERCEROS (no first-party Microsoft / tooling admin
    # rutinario). Reduce ruido — los consents a Microsoft Graph/Azure/Office por admins no se alertan.
    $flagged = @($rows | Where-Object { -not (Test-OAuthIgnored -App $_.App -Patterns $IgnoreAppPatterns) })

    return [pscustomobject]@{
        Available = $ok
        Rows      = $rows        # auditoría completa (se muestra en el reporte)
        Flagged   = $flagged     # subset accionable (alimenta alertas / risk)
        Summary   = if ($ok) { "Consents/permisos OAuth recientes: $(@($rows).Count) · a revisar (terceros): $(@($flagged).Count)" }
                    else      { "OAuth apps — auditoría no disponible (requiere AuditLog.Read.All)" }
    }
}

function Test-OAuthIgnored {
    # True si la app matchea un patrón de first-party Microsoft (ruido) => NO se flaggea.
    param([string] $App, [string[]] $Patterns)
    if (-not $App) { return $false }
    foreach ($p in @($Patterns)) { if ($p -and $App -like "*$p*") { return $true } }
    return $false
}
Export-ModuleMember -Function Get-OAuthAppRisk, Test-OAuthIgnored

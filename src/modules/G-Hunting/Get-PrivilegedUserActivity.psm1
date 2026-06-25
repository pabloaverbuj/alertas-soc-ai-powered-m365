# G-Hunting/Get-PrivilegedUserActivity.psm1
# #4 — Cambios en roles privilegiados (alta a rol, eligible) vía Graph directoryAudits.
# Requiere AuditLog.Read.All.

function Get-PrivilegedUserActivity {
    [CmdletBinding()]
    param([int] $LookbackDays = 7)
    $ok = $true; $rows = @()
    $since = (Get-Date).ToUniversalTime().AddDays(-$LookbackDays).ToString('o')
    try {
        $filter = "activityDateTime ge $since and (activityDisplayName eq 'Add member to role' or activityDisplayName eq 'Add eligible member to role' or activityDisplayName eq 'Add member to role completed (PIM activation)')"
        $aud = Invoke-SocGraph -Path "/auditLogs/directoryAudits?`$filter=$([uri]::EscapeDataString($filter))&`$top=50"
        $rows = @($aud | ForEach-Object {
            $role = (@($_.targetResources | ForEach-Object { ($_.modifiedProperties | Where-Object { $_.displayName -eq 'Role.DisplayName' }).newValue }) -join '') -replace '"',''
            [pscustomobject]@{
                Fecha   = $_.activityDateTime
                Accion  = $_.activityDisplayName
                Rol     = $role
                Target  = (@($_.targetResources | Where-Object { $_.type -eq 'User' } | ForEach-Object { $_.userPrincipalName }) -join ', ')
                Quien   = $_.initiatedBy.user.userPrincipalName
            }
        })
    } catch { Write-Warning "[ah-priv] directoryAudits no disponible (AuditLog.Read.All?). $($_.Exception.Message)"; $ok = $false }

    return [pscustomobject]@{
        Available = $ok
        Rows      = $rows
        Summary   = if ($ok) { "Cambios en roles privilegiados: $(@($rows).Count) (validar que sean esperados)" }
                    else      { "Actividad privilegiada — auditoría no disponible (requiere AuditLog.Read.All)" }
    }
}
Export-ModuleMember -Function Get-PrivilegedUserActivity

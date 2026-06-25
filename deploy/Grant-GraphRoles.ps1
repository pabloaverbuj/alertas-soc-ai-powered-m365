<#
.SYNOPSIS
  Asigna los app roles (Microsoft Graph + Defender) a la Managed Identity de aa-geonosis-soc-ai.
.DESCRIPTION
  Corre APARTE del deploy principal porque Microsoft.Graph y Az no conviven en la misma sesión
  (conflicto de assemblies: "Assembly with same name is already loaded", típico en Windows PowerShell 5.1).
  Ejecutar en una sesión NUEVA y limpia, idealmente PowerShell 7 (pwsh), SIN haber importado Az.
.PARAMETER MiObjectId
  ObjectId (PrincipalId) de la Managed Identity. Lo imprime el deploy principal, o se obtiene con Az:
    (Get-AzAutomationAccount -ResourceGroupName 'siem' -Name 'aa-geonosis-soc-ai').Identity.PrincipalId
.EXAMPLE
  pwsh -NoProfile -File .\Grant-GraphRoles.ps1 -MiObjectId 00000000-0000-0000-0000-000000000000
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $MiObjectId,
    [Parameter(Mandatory)][string] $TenantId
)
$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable Microsoft.Graph.Applications)) {
    throw "Falta Microsoft.Graph. Instalá: Install-Module Microsoft.Graph -Scope CurrentUser"
}
Import-Module Microsoft.Graph.Applications
Connect-MgGraph -TenantId $TenantId -Scopes 'AppRoleAssignment.ReadWrite.All','Application.Read.All' | Out-Null

function Grant-AppRoles {
    param([string]$ResourceAppId, [string[]]$Roles, [string]$MiId)
    $resSp = Get-MgServicePrincipal -Filter "appId eq '$ResourceAppId'"
    if (-not $resSp) { Write-Warning "SP de recurso $ResourceAppId no encontrado en el tenant."; return }
    $existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $MiId -All
    foreach ($r in $Roles) {
        $appRole = $resSp.AppRoles | Where-Object { $_.Value -eq $r -and $_.AllowedMemberTypes -contains 'Application' }
        if (-not $appRole) { Write-Warning "  ! rol '$r' inexistente en $($resSp.DisplayName) - omitido"; continue }
        if ($existing | Where-Object { $_.AppRoleId -eq $appRole.Id -and $_.ResourceId -eq $resSp.Id }) { Write-Host "  = $r (ya)"; continue }
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $MiId -PrincipalId $MiId `
            -ResourceId $resSp.Id -AppRoleId $appRole.Id | Out-Null
        Write-Host "  + $r"
    }
}

Write-Host "Asignando app roles de Microsoft Graph a la MI ($MiObjectId)..."
Grant-AppRoles -MiId $MiObjectId -ResourceAppId '00000003-0000-0000-c000-000000000000' -Roles @(
    'SecurityIncident.Read.All','SecurityAlert.Read.All','ThreatHunting.Read.All',
    'IdentityRiskyUser.Read.All','IdentityRiskEvent.Read.All',
    'Policy.Read.All','DeviceManagementManagedDevices.Read.All',
    'DeviceManagementConfiguration.Read.All',   # leer script GEO-CapturarUsuarioActivo + deviceRunStates (usuario real)
    'SecurityEvents.Read.All',                  # Microsoft Secure Score (#8 postura)
    'AuditLog.Read.All',                        # OAuth consents + cambios de rol privilegiado (#4 directoryAudits)
    'ExposureManagement.Read.All',   # M10 attack paths (omitido con warning si el tenant no lo expone)
    'Mail.Send'                      # envío de email del reporte
)
Write-Host "Asignando app role de Defender (WindowsDefenderATP) a la MI..."
Grant-AppRoles -MiId $MiObjectId -ResourceAppId 'fc780465-2017-40d4-a0c5-307022471b92' -Roles @('Machine.Read.All')   # M8

Write-Host ""
Write-Host "App roles asignados y EFECTIVOS (la asignacion directa a la MI es el consentimiento; NO requiere admin-consent)."
Write-Host "Verificar (opcional): Entra > Enterprise applications > filtro 'Managed Identities' > aa-geonosis-soc-ai > Permissions."

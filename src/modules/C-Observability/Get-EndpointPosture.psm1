# C-Observability/Get-EndpointPosture.psm1
# M8 — Endpoints: exposure/risk score (Defender for Endpoint) + vulns críticas + cruce con
# compliance de Intune (equipos noncompliant / sin cifrado).

function Get-EndpointPosture {
    [CmdletBinding()]
    param()

    # Defender for Endpoint — riesgo/exposición se lee por la API de Defender (recurso aparte de Graph):
    #   https://api.securitycenter.microsoft.com/api/machines
    # TODO deploy: dar a la MI el rol 'Machine.Read.All' en Microsoft Threat Protection / WDATP.
    try { $atpMachines = Get-DefenderMachines }
    catch { Write-Warning "[endpoint] Defender machines no disponible. $($_.Exception.Message)"; $atpMachines = @() }

    $highRisk = $atpMachines | Where-Object { $_.riskScore -in @('High','Medium') }
    $highExp  = $atpMachines | Where-Object { $_.exposureLevel -eq 'High' }

    # Inventario de usuario REAL por dispositivo (el primary user es siempre la cuenta de enrolamiento).
    # Lo provee el script Intune 'GEO-CapturarUsuarioActivo' (query user) via deviceRunStates.
    try { $userInv = Get-IntuneUserInventory }
    catch { Write-Warning "[endpoint] Inventario usuario real no disponible. $($_.Exception.Message)"; $userInv = @{} }

    # Cruce con Intune: noncompliant / sin BitLocker, con el usuario real mapeado.
    try { $intuneGaps = Get-IntuneComplianceGaps -Inventory $userInv }
    catch { Write-Warning "[endpoint] Intune compliance no disponible. $($_.Exception.Message)"; $intuneGaps = @() }

    return [pscustomobject]@{
        Summary    = "Endpoints — riesgo alto/medio: $($highRisk.Count) · exposición alta: $($highExp.Count) · Intune noncompliant/sin cifrado: $($intuneGaps.Count)"
        HighRisk   = $highRisk
        HighExposure = $highExp
        IntuneGaps = $intuneGaps
    }
}

function Get-DefenderMachines {
    $token = Get-SocToken -ResourceUrl 'https://api.securitycenter.microsoft.com'
    $resp  = Invoke-RestMethod -Uri 'https://api.securitycenter.microsoft.com/api/machines' `
                -Headers @{ Authorization = "Bearer $token" }
    return $resp.value
}

function Get-IntuneComplianceGaps {
    param([hashtable] $Inventory = @{})
    # noncompliant + sin cifrado, vía Graph managedDevices. User = usuario REAL (inventario) o el de enrolamiento.
    $devices = Invoke-SocGraph -Path "/deviceManagement/managedDevices?`$filter=complianceState eq 'noncompliant'"
    $devices | ForEach-Object {
        $key  = if ($_.deviceName) { $_.deviceName.ToLower() } else { '' }
        $real = if ($key -and $Inventory.ContainsKey($key)) { $Inventory[$key] } else { '(s/d)' }
        [pscustomobject]@{
            Name       = $_.deviceName
            User       = $real                       # usuario logueado real
            Enroll     = $_.userPrincipalName        # cuenta de enrolamiento (referencia)
            Compliance = $_.complianceState
            Encrypted  = $_.isEncrypted
        }
    }
}

function Get-IntuneUserInventory {
    # Mapa deviceName(lower) -> usuario real, leído del script Intune 'GEO-CapturarUsuarioActivo'.
    # Marker en resultMessage: "GEO-INVENTORY | host | fecha | <salida query user>". 1er token de la sesión = usuario.
    $map = @{}
    $scripts = Invoke-SocGraph -Version 'beta' -Path "/deviceManagement/deviceManagementScripts"
    $script  = $scripts | Where-Object { $_.displayName -eq 'GEO-CapturarUsuarioActivo' } | Select-Object -First 1
    if (-not $script) { Write-Warning "[endpoint] Script de inventario no encontrado."; return $map }

    $states = Invoke-SocGraph -Version 'beta' -Path "/deviceManagement/deviceManagementScripts/$($script.id)/deviceRunStates?`$expand=managedDevice"
    foreach ($st in $states) {
        $dev = $st.managedDevice.deviceName
        $msg = [string]$st.resultMessage
        if (-not $dev -or -not $msg) { continue }
        if ($msg -match 'GEO-INVENTORY \| [^|]+\| [^|]+\| (.+)$') {
            $sesion = $Matches[1].Trim()
            $user = if ($sesion -match 'SIN SESION|ERROR') { $sesion }
                    else { (($sesion -replace '^>', '').Trim() -split '\s+')[0] }
            if ($user) { $map[$dev.ToLower()] = $user }
        }
    }
    return $map
}

Export-ModuleMember -Function Get-EndpointPosture

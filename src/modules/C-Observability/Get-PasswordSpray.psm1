# C-Observability/Get-PasswordSpray.psm1
# M11b — Detección de password spray sobre SigninLogs.
# Separa sign-ins OK vs fallidos, arma listado de fallidos (usuario, motivo, locación, IP, dispositivo),
# identifica IPs origen de spray (1 IP -> muchos usuarios distintos) y compara semana vs semana anterior.
# Firma password spray: error 50126 (credencial inválida) repartido entre muchos usuarios desde pocas IPs.

function Get-PasswordSpray {
    [CmdletBinding()]
    param([int] $LookbackDays = 7, [int] $SprayUserThreshold = 5, [string[]] $TrustedEgressIps = @())

    $cur  = @(Invoke-SocKql -TimespanDays $LookbackDays       -Query (Get-SprayStatsKql "ago($($LookbackDays)d)" 'now()'))                       | Select-Object -First 1
    $prev = @(Invoke-SocKql -TimespanDays ($LookbackDays * 2) -Query (Get-SprayStatsKql "ago($($LookbackDays*2)d)" "ago($($LookbackDays)d)"))   | Select-Object -First 1

    # Allowlist de egress corporativo (NAT): se excluye del detector para evitar falsos positivos
    # (usuarios tras el mismo NAT tipeando mal la contraseña parecen spray). Inyectado en el KQL.
    $egressClause = ''
    if (@($TrustedEgressIps).Count -gt 0) {
        $list = ($TrustedEgressIps | ForEach-Object { '"' + ($_ -replace '"','') + '"' }) -join ', '
        $egressClause = "| where IPAddress !in ($list)"
    }

    # IPs origen de spray (una IP fallando credenciales contra muchos usuarios distintos)
    $ips = @(Invoke-SocKql -TimespanDays $LookbackDays -Query @"
SigninLogs
| where TimeGenerated >= ago(${LookbackDays}d) and ResultType == "50126"
$egressClause
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize Intentos = count(), UsuariosDistintos = dcount(UserPrincipalName), Usuarios = make_set(UserPrincipalName, 20) by IPAddress, Country
| where UsuariosDistintos >= ${SprayUserThreshold}
| order by UsuariosDistintos desc
| take 25
"@)

    # Detalle de sign-ins fallidos (los "malos"): usuario, motivo, locación, IP, dispositivo
    $detail = @(Invoke-SocKql -TimespanDays $LookbackDays -Query @"
SigninLogs
| where TimeGenerated >= ago(${LookbackDays}d) and ResultType != "0"
| extend Country = tostring(LocationDetails.countryOrRegion), City = tostring(LocationDetails.city), Device = tostring(DeviceDetail.displayName)
| summarize Intentos = count(), Ultimo = max(TimeGenerated) by UserPrincipalName, ResultType, ResultDescription, IPAddress, Country, City, Device
| order by Intentos desc
| take 60
"@)

    $wow = [pscustomobject]@{
        Fallidos         = (Get-SprayPct $cur.Fallidos          $prev.Fallidos)
        FallosPassword   = (Get-SprayPct $cur.FallosPassword    $prev.FallosPassword)
        UsuariosAtacados = (Get-SprayPct $cur.UsuariosAtacados  $prev.UsuariosAtacados)
        IPsOrigen        = (Get-SprayPct $cur.IPsOrigen         $prev.IPsOrigen)
    }

    $summary = "Password spray — sign-ins OK: $([int]$cur.Exitosos) / fallidos: $([int]$cur.Fallidos) (WoW $(Show-SprayPct $wow.Fallidos)) · " +
               "fallos de credencial (50126): $([int]$cur.FallosPassword) (WoW $(Show-SprayPct $wow.FallosPassword)) · " +
               "usuarios atacados: $([int]$cur.UsuariosAtacados) (WoW $(Show-SprayPct $wow.UsuariosAtacados)) · IPs origen de spray: $(@($ips).Count)"

    return [pscustomobject]@{
        Summary   = $summary
        StatsCur  = $cur
        StatsPrev = $prev
        WoW       = $wow
        SprayIPs  = $ips
        Detail    = $detail
        AtRisk    = (@($ips).Count -gt 0)
    }
}

function Get-SprayStatsKql {
    param([string] $Start, [string] $End)
    @"
SigninLogs
| where TimeGenerated between ($Start .. $End)
| summarize Total=count(), Exitosos=countif(ResultType=="0"), Fallidos=countif(ResultType!="0"),
            FallosPassword=countif(ResultType=="50126"),
            UsuariosAtacados=dcountif(UserPrincipalName, ResultType=="50126"),
            IPsOrigen=dcountif(IPAddress, ResultType=="50126")
"@
}

function Get-SprayPct {
    param($Cur, $Prev)
    $c = [double]($Cur  | ForEach-Object { $_ }); if (-not $c) { $c = 0 }
    $p = [double]($Prev | ForEach-Object { $_ }); if (-not $p) { $p = 0 }
    if ($p -eq 0) { if ($c -eq 0) { return 0 } else { return $null } }   # null = nuevo (sin base previa)
    [math]::Round((($c - $p) / $p) * 100)
}

function Show-SprayPct {
    param($Pct)
    if ($null -eq $Pct) { return 'nuevo' }
    if ($Pct -gt 0)  { return "+$Pct% (peor)" }
    if ($Pct -lt 0)  { return "$Pct% (mejor)" }
    '0% (igual)'
}

Export-ModuleMember -Function Get-PasswordSpray, Show-SprayPct

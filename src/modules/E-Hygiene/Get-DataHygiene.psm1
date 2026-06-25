# E-Hygiene/Get-DataHygiene.psm1
# M15 — Higiene de datos/costos: GB ingeridos por tabla y tablas caras sin uso (ingieren pero
# ninguna analytics rule las consulta = plata tirada). Insumo para las recos de data value.

function Get-DataHygiene {
    [CmdletBinding()]
    param([int] $LookbackDays = 30)

    # Volumen por tabla (GB) últimos N días
    $usage = Invoke-SocKql -TimespanDays $LookbackDays -Query @"
Usage
| where TimeGenerated >= ago(${LookbackDays}d)
| where IsBillable == true
| summarize GB = round(sum(Quantity) / 1024, 2) by DataType
| order by GB desc
"@

    # Tablas que ingieren pero no son referenciadas por ninguna analytics rule activa.
    # (Aproximación: cruce contra la lista de tablas usadas por reglas — TODO completar en deploy
    #  con el inventario de analytics rules; por ahora marca las de mayor volumen para revisión.)
    $topCost = $usage | Select-Object -First 10

    return [pscustomobject]@{
        Summary   = "Higiene datos — ingesta total: $([math]::Round((($usage.GB) | Measure-Object -Sum).Sum,1)) GB/${LookbackDays}d · top tabla: $($topCost[0].DataType) ($($topCost[0].GB) GB)"
        Usage     = $usage
        TopCost   = $topCost
    }
}

Export-ModuleMember -Function Get-DataHygiene

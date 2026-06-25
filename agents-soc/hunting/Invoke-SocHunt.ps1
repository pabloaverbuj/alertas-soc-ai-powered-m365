<#
.SYNOPSIS
  DIAGNÓSTICO: ¿hay telemetría de endpoint en Defender XDR para los hosts del incidente?
  Determina si las tablas Device* están pobladas / los hosts onboarded a MDE, o si la evidencia
  del incidente vive solo en AlertEvidence (data ingestada sin sensor de endpoint).
#>
$ctx = Connect-SocContext

$queries = [ordered]@{
  # ¿Están los 3 hosts conocidos por MDE? estado de onboarding
  'deviceinfo_hosts' = @'
DeviceInfo
| where DeviceName has_any ("jango-fett38","desktop-qoj8q45","jango-fett14")
| summarize arg_max(Timestamp, OnboardingStatus, OSPlatform) by DeviceName
'@
  # ¿La tabla de procesos está poblada en general? (ult 7d)
  'deviceprocess_total' = @'
DeviceProcessEvents
| where Timestamp > ago(7d)
| summarize Procesos=count(), Devices=dcount(DeviceName)
'@
  # ¿Cuántos devices ve MDE en total?
  'mde_device_count' = @'
DeviceInfo
| summarize Devices=dcount(DeviceName)
'@
  # La evidencia del alert en advanced hunting (AlertEvidence): ¿qué entidades/columnas trae?
  'alertevidence_stealer' = @'
AlertEvidence
| where Timestamp > ago(14d)
| where Title has "stealing"
| project Timestamp, Title, DeviceName, AccountName, FileName, RemoteUrl, RemoteIP, EntityType
| take 30
'@
}

foreach ($name in $queries.Keys) {
    try {
        $rows = @(Invoke-SocHunting -Query $queries[$name])
        $json = ($rows | ConvertTo-Json -Depth 6 -Compress); if (-not $json) { $json = '[]' }
        Write-Output ("HUNT|{0}|{1}|{2}" -f $name, @($rows).Count, $json)
    } catch {
        Write-Output ("HUNT|{0}|ERR|{1}" -f $name, $_.Exception.Message)
    }
}
Write-Output "HUNT|done"

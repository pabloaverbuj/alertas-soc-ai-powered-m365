# B-Detection/Get-SocIncidents.psm1
# M5 — Inventario de incidentes (Defender XDR + Sentinel) con entidades y mapeo MITRE.

function Get-SocIncidents {
    [CmdletBinding()]
    param(
        [int] $LookbackDays = 7,
        [string[]] $CriticalSeverities = @('high'),
        [bool] $DeepFetch = $true,                  # fetch profundo alerts_v2 cuando el expand shallow no trae entidades
        [int]  $MaxAlertsPerIncident = 8            # tope de alerts a fetchear por incidente (control de costo)
    )

    $since = (Get-Date).ToUniversalTime().AddDays(-$LookbackDays).ToString('o')
    # Graph Security API unifica incidentes de XDR + Sentinel.
    $filter = "createdDateTime ge $since"
    # /security/incidents tope $top=50; Invoke-SocGraph pagina solo vía @odata.nextLink.
    $inc = Invoke-SocGraph -Path "/security/incidents?`$filter=$filter&`$expand=alerts&`$top=50"

    $kqlCache = @{}   # memoiza el fallback KQL por título (incidentes duplicados comparten título =>
                      # 1 sola query, evita throttling de Log Analytics y resultados inconsistentes).
    $items = foreach ($i in $inc) {
        $techniques = @($i.alerts.mitreTechniques | Select-Object -Unique)
        # 1) Extracción shallow desde el $expand=alerts. Barata, cubre la mayoría.
        $ents = @(Get-IncidentEntities -Incident $i)
        # 2) Fallback Graph: el $expand=alerts del listado NO siempre puebla alerts/evidence (Graph lo
        #    dropea, sobre todo al paginar). Si quedó vacío, fetch profundo /incidents/{id}/alerts -> alerts_v2/{id}.
        if ($DeepFetch -and @($ents).Count -eq 0) {
            $ents = @(Get-IncidentEntitiesDeep -IncidentId $i.id -MaxAlerts $MaxAlertsPerIncident)
        }
        # 3) Fallback KQL (Sentinel): los incidentes tipo Sentinel no exponen alerts por Graph
        #    (colección vacía). Sus entidades viven en SecurityAlert del workspace. El id de Graph NO
        #    es el IncidentNumber ni el ProviderIncidentId de Sentinel (3 esquemas distintos) -> se
        #    correlaciona por TÍTULO (SecurityIncident.Title -> AlertIds -> SecurityAlert.Entities).
        if ($DeepFetch -and @($ents).Count -eq 0 -and $i.displayName) {
            $key = $i.displayName.Trim()
            if (-not $kqlCache.ContainsKey($key)) {
                $kqlCache[$key] = @(Get-IncidentEntitiesKql -Title $key -LookbackDays ([math]::Max($LookbackDays, 30)))
            }
            $ents = @($kqlCache[$key])
        }
        [pscustomobject]@{
            Id         = $i.id
            Title      = $i.displayName
            Severity   = $i.severity
            Status     = $i.status
            Created    = $i.createdDateTime
            Mitre      = $techniques
            AlertCount = @($i.alerts).Count
            Entities   = @($ents)
        }
    }

    $critical = $items | Where-Object { $_.Severity -in $CriticalSeverities -and $_.Status -ne 'resolved' }
    return [pscustomobject]@{
        Summary  = New-IncidentSummary -Items $items -Critical $critical
        Items    = $items
        Critical = $critical          # alimenta el disparo out-of-band (M2)
    }
}

function Get-IncidentEntities {
    # Extrae entidades (usuarios/devices/IPs/mailboxes/apps/archivos) de la evidencia polimórfica
    # de Graph Security. Cada alert.evidence[] tiene un @odata.type distinto; recorremos todas las
    # formas conocidas para no perder identidades (ej. infostealer trae deviceEvidence/fileEvidence,
    # no userAccount). Devuelve lista plana de strings únicos.
    param([Parameter(Mandatory)] $Incident)
    $out = New-Object System.Collections.Generic.List[string]
    $add = { param($v) if ($v -and "$v".Trim()) { $out.Add("$v".Trim()) } }
    foreach ($al in @($Incident.alerts)) {
        foreach ($e in @($al.evidence)) {
            # Cuenta: solo el UPN (no accountName/displayName: meten "Nombre Apellido" y SAM bare
            # que ensucian y se clasifican mal). Si no hay UPN, caer a accountName como último recurso.
            if ($e.userAccount.userPrincipalName) { & $add $e.userAccount.userPrincipalName }
            elseif ($e.userAccount.accountName)   { & $add $e.userAccount.accountName }
            & $add $e.deviceDnsName              # deviceEvidence
            & $add $e.deviceEvidence.deviceDnsName
            & $add $e.ipAddress                  # ipEvidence
            & $add $e.ipEvidence.ipAddress
            & $add $e.primaryAddress             # mailboxEvidence
            & $add $e.mailboxEvidence.primaryAddress
            & $add $e.fileDetails.fileName       # fileEvidence
            & $add $e.appId                      # oauthApplicationEvidence
            & $add $e.displayName                # oauthApplicationEvidence / cloudApplicationEvidence
        }
    }
    return @($out | Where-Object { $_ } | Select-Object -Unique)
}

function Get-IncidentEntitiesDeep {
    # Fetch profundo en dos pasos para incidentes cuyo $expand=alerts del listado llega sin evidence:
    #   (1) /security/incidents/{id}/alerts -> alerts con su id (la colección NO incluye el array evidence).
    #   (2) por cada alert id, GET /security/alerts_v2/{id} -> alert con evidence completa -> extraer entidades.
    # Acotado por -MaxAlerts (costo). Tolerante: incidentes Sentinel cuyos alerts no se exponen por este
    # endpoint devuelven colección vacía (value:[]) -> sin id -> se saltan (la evidencia vive en consola Defender).
    param([Parameter(Mandatory)][string] $IncidentId, [int] $MaxAlerts = 8)
    $out = New-Object System.Collections.Generic.List[string]
    try {
        $alerts = @(Invoke-SocGraph -Path "/security/incidents/$IncidentId/alerts") | Select-Object -First $MaxAlerts
        foreach ($al in $alerts) {
            if (-not $al.id) { continue }   # envelope vacío (value:[]) o alert sin id -> saltar
            $full = @(Invoke-SocGraph -Path "/security/alerts_v2/$($al.id)") | Select-Object -First 1
            if (-not $full) { continue }
            $pseudo = [pscustomobject]@{ alerts = @($full) }
            foreach ($e in @(Get-IncidentEntities -Incident $pseudo)) { if ($e) { $out.Add($e) } }
        }
    } catch { Write-Warning "[incidents] deep fetch $IncidentId falló: $($_.Exception.Message)" }
    if (@($out).Count -eq 0) { Write-Verbose "[incidents] $IncidentId sin entidades vía Graph (evidencia probablemente solo en consola Defender)." }
    return @($out | Where-Object { $_ } | Select-Object -Unique)
}

function Get-IncidentEntitiesKql {
    # Fallback final para incidentes Sentinel (los que Graph no expone alerts): consulta SecurityAlert
    # del workspace y extrae entidades (account/host/ip/url/mailbox/file) parseando la columna Entities
    # (JSON) directo en KQL. Correlación por TÍTULO: el id de Graph no coincide con IncidentNumber ni
    # ProviderIncidentId de Sentinel. SecurityIncident.Title -> AlertIds -> SecurityAlert.Entities.
    param([Parameter(Mandatory)][string] $Title, [int] $LookbackDays = 30)
    # Escapar para KQL (string entre comillas dobles): backslash y comilla doble.
    $safe = $Title.Replace('\', '\\').Replace('"', '\"')
    $kql = @'
SecurityIncident
| where Title =~ "__TITLE__"
| summarize arg_max(TimeGenerated, AlertIds) by IncidentNumber
| mv-expand AlertId = todynamic(AlertIds) to typeof(string)
| join kind=inner (
    SecurityAlert
    | summarize arg_max(TimeGenerated, Entities) by SystemAlertId
  ) on $left.AlertId == $right.SystemAlertId
| mv-expand Entity = todynamic(Entities)
| extend EType = tolower(tostring(Entity.Type))
| extend Val = case(
    EType == "account", iff(isnotempty(tostring(Entity.UPNSuffix)), strcat(tostring(Entity.Name), "@", tostring(Entity.UPNSuffix)), ""),
    EType == "host",    coalesce(tostring(Entity.HostName), tostring(Entity.NetBiosName)),
    EType == "ip",      tostring(Entity.Address),
    EType == "url",     tostring(Entity.Url),
    EType == "mailbox", tostring(Entity.MailboxPrimaryAddress),
    EType == "file",    tostring(Entity.Name),
    "")
| where isnotempty(Val)
| distinct Val
'@.Replace('__TITLE__', $safe)
    try {
        $rows = @(Invoke-SocKql -Query $kql -TimespanDays $LookbackDays)
        return @($rows | ForEach-Object { $_.Val } | Where-Object { $_ } | Select-Object -Unique)
    } catch { Write-Warning "[incidents] KQL SecurityAlert (titulo '$Title') falló: $($_.Exception.Message)"; return @() }
}

function New-IncidentSummary {
    param($Items, $Critical)
    $bySev = $Items | Group-Object Severity | ForEach-Object { "$($_.Name): $($_.Count)" }
    @"
Incidentes ($($Items.Count) total): $($bySev -join ' · ')
Críticos abiertos: $($Critical.Count)
Top técnicas MITRE: $((($Items.Mitre | Group-Object | Sort-Object Count -Descending | Select-Object -First 5).Name) -join ', ')
"@
}

Export-ModuleMember -Function Get-SocIncidents, Get-IncidentEntities, Get-IncidentEntitiesDeep, Get-IncidentEntitiesKql

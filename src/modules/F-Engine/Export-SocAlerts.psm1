# F-Engine/Export-SocAlerts.psm1
# Puente runbook -> agentes SOC interactivos. Toma las señales críticas que ya calcula el
# orquestador y las NORMALIZA al schema del "SOC Alert Normalizer" (ver agents-soc/), para que
# el lado local (Import-SocAlerts.ps1 -> agents-soc/inbox/) las ingiera y soc-casemanager abra casos.
#
# Persistencia: el orquestador guarda el array devuelto en la Automation Variable
# 'GeonosisSocAi-SocAlerts' (Set-SocState). El bridge local la lee con Get-AzAutomationVariable.
#
# alertId es ESTABLE (= clave de la señal, ej "INC:<id>") => el bridge deduplica re-corridas.

function Get-SocAlertRouting {
    # Mapea (tipo de señal, título) -> category + recommendedPlaybook del catálogo de playbooks.
    param([string] $Kind, [string] $Title = '')
    $t = $Title.ToLowerInvariant()
    switch ($Kind) {
        'INC' {
            if ($t -match 'phish|business email|bec|impersonat')       { return @{ category='phishing_bec';          playbook='M365_ACCOUNT_COMPROMISE_BEC' } }
            if ($t -match 'consent|oauth|application')                 { return @{ category='oauth_app_consent';      playbook='M365_OAUTH_CONSENT' } }
            if ($t -match 'password spray|spray')                      { return @{ category='password_spray';         playbook='M365_PASSWORD_SPRAY' } }
            if ($t -match 'device code|devicecode')                    { return @{ category='device_code_phishing';   playbook='M365_DEVICE_CODE_PHISHING' } }
            if ($t -match 'forward|inbox rule|mailbox')                { return @{ category='mailbox_forwarding';     playbook='M365_MAILBOX_FORWARDING' } }
            # infostealer / credential theft / malware => compromiso de cuenta (token/credencial robada)
            return @{ category='phishing_bec'; playbook='M365_ACCOUNT_COMPROMISE_BEC' }
        }
        'HRU'        { return @{ category='risky_user';            playbook='M365_ACCOUNT_COMPROMISE_BEC' } }
        'DEVICECODE' { return @{ category='device_code_phishing';  playbook='M365_DEVICE_CODE_PHISHING' } }
        'OAUTH'      { return @{ category='oauth_app_consent';     playbook='M365_OAUTH_CONSENT' } }
        'SPRAY'      { return @{ category='password_spray';        playbook='M365_PASSWORD_SPRAY' } }
        'PHISH'      { return @{ category='phishing_bec';          playbook='M365_ACCOUNT_COMPROMISE_BEC' } }
        'AP'         { return @{ category='attack_path';           playbook='UNMAPPED' } }   # estructural -> posture
        'DRIFT'      { return @{ category='config_drift';          playbook='UNMAPPED' } }   # estructural -> posture
        default      { return @{ category='unknown';               playbook='UNMAPPED' } }
    }
}

function Expand-SocEntityList {
    # Normaliza una lista de entidades: KQL make_set/dynamic vuelve de Log Analytics como STRING JSON
    # ('["a","b"]') => hay que parsearlo para no doble-codificar. Acepta array, string-JSON o escalar.
    param($Value)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($v in @($Value)) {
        if ($null -eq $v) { continue }
        $s = "$v".Trim()
        if ($s.StartsWith('[')) {
            try { foreach ($x in (@($s | ConvertFrom-Json))) { if ($x) { $out.Add("$x") } }; continue } catch {}
        }
        if ($s) { $out.Add($s) }
    }
    return @($out | Select-Object -Unique)
}

function New-SocAlert {
    param([string]$AlertId, [string]$Source, [string]$Kind, [string]$Title, [string]$Severity,
          [string]$Created, [hashtable]$Entities)
    $r = Get-SocAlertRouting -Kind $Kind -Title $Title
    $ents = @{ users=@(); devices=@(); ips=@(); messages=@(); urls=@(); files=@(); apps=@() }
    if ($Entities) { foreach ($k in $Entities.Keys) { $ents[$k] = @(Expand-SocEntityList -Value $Entities[$k]) } }
    [ordered]@{
        caseId            = ''                                   # lo asigna soc-casemanager al ingerir
        alertId           = $AlertId                             # estable -> dedup
        source            = $Source
        category          = $r.category
        title             = $Title
        severity          = if ($Severity) { $Severity } else { 'medium' }
        createdDateTime   = if ($Created) { $Created } else { (Get-Date).ToUniversalTime().ToString('o') }
        entities          = $ents
        recommendedPlaybook = $r.playbook
        status            = 'new'
    }
}

function Export-SocAlerts {
    <#
      Construye el array de alertas normalizadas a partir de las señales que el orquestador ya tiene.
      Devuelve [object[]]. El orquestador lo persiste en 'GeonosisSocAi-SocAlerts'.
      Solo incluye señales ACCIONABLES (las mismas que disparan el modo critical) + hunting de alto valor.
    #>
    [CmdletBinding()]
    param(
        $Incidents, $Identity, $AttackPaths, $Drift, $DeviceCode, $PasswordSpray, $Hunting,
        [int] $LookbackDays = 7
    )
    $alerts = New-Object System.Collections.Generic.List[object]
    $now    = (Get-Date).ToUniversalTime().ToString('o')

    # Incidentes high/critical abiertos (Defender XDR + Sentinel)
    foreach ($i in @($Incidents.Critical)) {
        # Las entidades del incidente vienen como lista plana de strings (Graph o KQL SecurityAlert).
        # Clasificarlas por heurística para no meter URLs/IPs/hosts dentro de "users".
        $eu=@(); $eip=@(); $eurl=@(); $edev=@()
        foreach ($x in @($i.Entities)) {
            if (-not $x) { continue }
            $s = "$x"
            if ($s -match '@')                                              { $eu  += $s }   # account UPN
            elseif ($s -match '^\d{1,3}(\.\d{1,3}){3}$' -or $s -match '^[0-9a-fA-F:]+:[0-9a-fA-F:]+$') { $eip += $s }  # ipv4/ipv6
            elseif ($s -match '^[^\s/]+\.[a-z]{2,}(/.*)?$')                  { $eurl += $s }  # dominio/url
            else                                                            { $edev += $s }  # hostname
        }
        $alerts.Add( (New-SocAlert -AlertId "INC:$($i.Id)" -Source 'Defender XDR | Sentinel' -Kind 'INC' `
            -Title $i.Title -Severity $i.Severity -Created $i.Created `
            -Entities @{ users=$eu; ips=$eip; urls=$eurl; devices=$edev }) )
    }
    # Usuarios high-risk (Entra ID Protection)
    foreach ($u in @($Identity.HighRiskUsers)) {
        $alerts.Add( (New-SocAlert -AlertId "HRU:$($u.userPrincipalName)" -Source 'Entra ID' -Kind 'HRU' `
            -Title "Usuario en riesgo alto: $($u.userPrincipalName)" -Severity 'high' -Created $now `
            -Entities @{ users=@($u.userPrincipalName) }) )
    }
    # Device-code en riesgo (Kali365)
    if ($DeviceCode -and $DeviceCode.AtRisk -and @($DeviceCode.SignIns).Count -gt 0) {
        $dcUsers = @($DeviceCode.SignIns | ForEach-Object { $_.UserPrincipalName } | Where-Object { $_ } | Select-Object -Unique)
        $alerts.Add( (New-SocAlert -AlertId 'DEVICECODE:atRisk' -Source 'Entra ID' -Kind 'DEVICECODE' `
            -Title 'Sign-ins device-code en riesgo (CA de bloqueo no enforced)' -Severity 'high' -Created $now `
            -Entities @{ users=$dcUsers }) )
    }
    # Attack paths a crown jewels (Azure Resource Graph / Defender for Cloud) — estructural
    foreach ($p in @($AttackPaths.ToCrown)) {
        $alerts.Add( (New-SocAlert -AlertId "AP:$($p.Id)" -Source 'Defender XDR' -Kind 'AP' `
            -Title "Attack path a crown jewel: $($p.Name)" -Severity 'high' -Created $now `
            -Entities @{}) )
    }
    # Config drift high (ej CA report-only) — estructural
    foreach ($d in @($Drift.High)) {
        $alerts.Add( (New-SocAlert -AlertId "DRIFT:$($d.Policy)" -Source 'Entra ID' -Kind 'DRIFT' `
            -Title "Config drift ($($d.Type)): $($d.Policy)" -Severity 'high' -Created $now -Entities @{}) )
    }
    # Password spray (IPs concentradas) — propiedad real: SprayIPs (filas KQL: IPAddress, UsuariosDistintos, Usuarios)
    foreach ($ip in @($PasswordSpray.SprayIPs)) {
        $alerts.Add( (New-SocAlert -AlertId "SPRAY:$($ip.IPAddress)" -Source 'Entra ID' -Kind 'SPRAY' `
            -Title "Password spray desde $($ip.IPAddress) ($($ip.UsuariosDistintos) usuarios)" -Severity 'medium' -Created $now `
            -Entities @{ ips=@($ip.IPAddress); users=@($ip.Usuarios) }) )
    }
    # Hunting OAuth: solo los consents FLAGGED (terceros / publisher no verificado), no el ruido
    # de tooling Microsoft first-party. Fallback a .Rows si el módulo no expone .Flagged.
    if ($Hunting.OAuthApps -and $Hunting.OAuthApps.Available) {
        $oauthItems = if ($null -ne $Hunting.OAuthApps.PSObject.Properties['Flagged']) { $Hunting.OAuthApps.Flagged } else { $Hunting.OAuthApps.Rows }
        foreach ($a in @($oauthItems)) {
            $aid = ("OAUTH:{0}:{1}" -f $a.App, $a.Fecha)
            $alerts.Add( (New-SocAlert -AlertId $aid -Source 'Entra ID' -Kind 'OAUTH' `
                -Title "OAuth consent a revisar: $($a.App) ($($a.Accion))" -Severity 'medium' -Created $a.Fecha `
                -Entities @{ apps=@($a.App); users=@($a.Quien) }) )
        }
    }
    # Hunting phishing: clicks que PASARON la advertencia (Safe Links) — riesgo real
    if ($Hunting.UrlClicks -and $Hunting.UrlClicks.Available) {
        foreach ($c in @($Hunting.UrlClicks.Rows | Where-Object { $_.IsClickedThrough -eq 1 })) {
            $aid = ("PHISH:{0}:{1}" -f $c.AccountUpn, $c.Timestamp)
            $alerts.Add( (New-SocAlert -AlertId $aid -Source 'Defender XDR' -Kind 'PHISH' `
                -Title "Click-through a URL con amenaza: $($c.AccountUpn)" -Severity 'high' -Created $c.Timestamp `
                -Entities @{ users=@($c.AccountUpn); urls=@($c.Url) }) )
        }
    }

    return $alerts.ToArray()
}

Export-ModuleMember -Function Export-SocAlerts, New-SocAlert, Get-SocAlertRouting, Expand-SocEntityList

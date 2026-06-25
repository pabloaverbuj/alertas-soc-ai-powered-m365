# F-Engine/Get-SocRiskEngine.psm1
# Motor de riesgo (#2): convierte los hallazgos crudos en (a) findings normalizados con ESTADO
# vs el reporte anterior (nuevo/recurrente/resuelto/empeoró/mejoró) y (b) RISK SCORE por entidad
# (usuario/dispositivo/IP) acumulando señales de todos los módulos. Puro: opera sobre $Data + $PrevState.

function Get-SocSevScore { param([string]$s) switch -Regex (([string]$s).ToLower()) { 'crit' {100;break} 'high' {70;break} 'medium|med' {40;break} 'low' {15;break} default {25} } }

function Add-SocFinding {
    param([System.Collections.Generic.List[object]]$List,$Key,$Type,$Sev,$Entity,$Title)
    $List.Add([pscustomobject]@{ Key=$Key; Type=$Type; Severity=$Sev; Entity=$Entity; Title=$Title; Score=(Get-SocSevScore $Sev) })
}
function Add-SocEntity {
    param([hashtable]$Map,$Name,$Type,$Pts,$Sig)
    if (-not $Name) { return }
    $k = $Name.ToString().ToLower()
    if (-not $Map.ContainsKey($k)) { $Map[$k] = [pscustomobject]@{ Name=$Name; Type=$Type; Score=0; Signals=(New-Object System.Collections.Generic.List[string]) } }
    $Map[$k].Score += $Pts; $Map[$k].Signals.Add($Sig)
}
function Test-SocEntityType { param($s) if ($s -match '@') { 'user' } elseif ($s -match '^\d{1,3}(\.\d{1,3}){3}') { 'ip' } else { 'device' } }

function Get-SocRiskEngine {
    [CmdletBinding()]
    param([System.Collections.IDictionary] $Data, [object] $PrevState = $null)

    # ---------------- (a) FINDINGS NORMALIZADOS ----------------
    $cur = New-Object System.Collections.Generic.List[object]
    foreach ($i in @($Data.Incidents.Items)) {
        if ($i.Severity -in @('high','medium')) { Add-SocFinding $cur "INC:$($i.Id)" 'Incidente' $i.Severity (@($i.Entities) -join ', ') $i.Title }
    }
    foreach ($u in @($Data.Identity.HighRiskUsers)) { Add-SocFinding $cur "HRU:$($u.userPrincipalName)" 'Identidad' 'high' $u.userPrincipalName 'Usuario de alto riesgo (ID Protection)' }
    foreach ($d in @($Data.Drift.Findings))         { Add-SocFinding $cur "DRIFT:$($d.Policy)" 'ConfigDrift' $d.Severity $d.Policy $d.Type }
    foreach ($g in @($Data.Coverage.Gaps))          { Add-SocFinding $cur "GAP:$($g.Scenario)" 'Cobertura' 'medium' '-' "Gap de cobertura: $($g.Scenario)" }
    foreach ($p in @($Data.AttackPaths.ToCrown))    { Add-SocFinding $cur "AP:$($p.Id)" 'RutaAtaque' 'high' $p.Name 'Ruta de ataque a crown jewel' }
    foreach ($ip in @($Data.PasswordSpray.SprayIPs)){ Add-SocFinding $cur "SPRAYIP:$($ip.IPAddress)" 'PasswordSpray' 'medium' $ip.IPAddress "Spray desde IP ($($ip.UsuariosDistintos) usuarios)" }
    if ($Data.DeviceCode.AtRisk) { Add-SocFinding $cur 'DEVICECODE' 'Identidad' 'high' 'tenant' 'Device-code flow no bloqueado' }
    foreach ($o in @($Data.Hunting.OAuthApps.Rows))   { Add-SocFinding $cur "OAUTH:$($o.App)" 'OAuth' 'medium' $o.Quien "Consent OAuth: $($o.App)" }
    foreach ($pr in @($Data.Hunting.PrivActivity.Rows)){ Add-SocFinding $cur "PRIVCHG:$($pr.Target):$($pr.Rol)" 'Identidad' 'medium' $pr.Target "Cambio de rol privilegiado: $($pr.Rol)" }

    $prevMap = @{}
    if ($PrevState -and $PrevState.findings) { foreach ($f in @($PrevState.findings)) { if ($f.Key) { $prevMap[$f.Key] = [int]$f.Score } } }

    $findings = foreach ($f in $cur) {
        $state = 'nuevo'; $delta = ''
        if ($prevMap.ContainsKey($f.Key)) {
            $pv = $prevMap[$f.Key]
            if     ($f.Score -gt $pv) { $state='empeoró'; $delta="+$($f.Score-$pv)" }
            elseif ($f.Score -lt $pv) { $state='mejoró';  $delta="$($f.Score-$pv)" }
            else                      { $state='recurrente' }
        }
        [pscustomobject]@{ Key=$f.Key; Type=$f.Type; Severity=$f.Severity; Entity=$f.Entity; Title=$f.Title; Score=$f.Score; State=$state; Delta=$delta }
    }
    $findings = @($findings)
    $curKeys = @($findings.Key)
    $resolved = foreach ($k in $prevMap.Keys) { if ($k -notin $curKeys) {
        [pscustomobject]@{ Key=$k; Type=($k -split ':')[0]; Severity='-'; Entity='-'; Title='(ya no presente)'; Score=0; State='resuelto'; Delta='' } } }
    $findings = @($findings) + @($resolved)

    # ---------------- (b) RISK SCORE POR ENTIDAD ----------------
    $priv = @(); try { $priv = @($Data.CrownJewels.identities | Where-Object { $_.tier -eq 0 } | ForEach-Object { [string]$_.value }) } catch {}
    $ent = @{}
    foreach ($u in @($Data.Identity.HighRiskUsers)) { Add-SocEntity $ent $u.userPrincipalName 'user' 45 'ID Protection: alto riesgo' }
    foreach ($u in @($Data.Identity.RiskyUsers | Where-Object { $_.riskLevel -eq 'medium' })) { Add-SocEntity $ent $u.userPrincipalName 'user' 20 'ID Protection: riesgo medio' }
    foreach ($d in @($Data.Identity.Detections)) { Add-SocEntity $ent $d.userPrincipalName 'user' 20 "Detección de riesgo: $($d.riskEventType)" }
    foreach ($i in @($Data.Incidents.Items | Where-Object { $_.Severity -in @('high','medium') })) {
        foreach ($e in @($i.Entities)) { $pts = $(if($i.Severity -eq 'high'){50}else{30}); Add-SocEntity $ent $e (Test-SocEntityType $e) $pts "En incidente $($i.Severity): $($i.Title)" }
    }
    foreach ($g in @($Data.Endpoints.IntuneGaps)) {
        Add-SocEntity $ent $g.Name 'device' 25 'Intune noncompliant'
        if ($g.User -and $g.User -ne '(s/d)') { Add-SocEntity $ent $g.User 'user' 10 "Usuario de endpoint noncompliant ($($g.Name))" }
    }
    foreach ($m in @($Data.Endpoints.HighExposure)) { if ($m.computerDnsName) { Add-SocEntity $ent $m.computerDnsName 'device' 40 'Defender: exposición alta' } }
    foreach ($ip in @($Data.PasswordSpray.SprayIPs)) { Add-SocEntity $ent $ip.IPAddress 'ip' 35 "Origen de password spray ($($ip.UsuariosDistintos) usuarios)" }
    foreach ($s in @($Data.PasswordSpray.Detail | Select-Object -First 40)) { Add-SocEntity $ent $s.UserPrincipalName 'user' 8 'Objetivo de sign-ins fallidos' }
    foreach ($r in @($Data.Hunting.EmailPhishing.Rows)) { Add-SocEntity $ent $r.RecipientEmailAddress 'user' 15 "Destinatario de phishing/malware ($($r.ThreatTypes))" }
    foreach ($r in @($Data.Hunting.UrlClicks.Rows | Where-Object { $_.IsClickedThrough -eq 1 })) { Add-SocEntity $ent $r.AccountUpn 'user' 25 'Click a URL maliciosa (clicked-through)' }
    foreach ($r in @($Data.Hunting.PrivActivity.Rows)) { Add-SocEntity $ent $r.Target 'user' 20 "Cambio de rol privilegiado: $($r.Rol)" }

    foreach ($k in @($ent.Keys)) {
        $e = $ent[$k]
        if ($e.Type -eq 'user' -and ($priv | Where-Object { $e.Name -like "*$_*" -or $_ -like "*$($e.Name)*" })) {
            $e.Score = [int]($e.Score * 1.5); $e.Signals.Add('Identidad privilegiada (crown jewel)')
        }
    }

    $entityRisk = $ent.Values | Where-Object { $_.Score -gt 0 } | ForEach-Object {
        $lvl = if ($_.Score -ge 110) { 'Crítico' } elseif ($_.Score -ge 70) { 'Alto' } elseif ($_.Score -ge 40) { 'Medio' } else { 'Bajo' }
        [pscustomobject]@{ Entity=$_.Name; Type=$_.Type; Score=$_.Score; Level=$lvl; Signals=(($_.Signals | Select-Object -Unique) -join ' · ') }
    } | Sort-Object Score -Descending

    $byState  = $findings | Group-Object State | ForEach-Object { "$($_.Name): $($_.Count)" }
    $critAlto = @($entityRisk | Where-Object { $_.Level -in @('Crítico','Alto') }).Count
    $summary  = "Motor de riesgo — entidades evaluadas: $(@($entityRisk).Count) (crítico/alto: $critAlto). Hallazgos por estado: $($byState -join ' · ')"

    return [pscustomobject]@{
        Summary      = $summary
        Findings     = $findings
        EntityRisk   = $entityRisk
        StateForSave = @($cur | ForEach-Object { [pscustomobject]@{ Key=$_.Key; Score=$_.Score; Severity=$_.Severity } })
    }
}

Export-ModuleMember -Function Get-SocRiskEngine

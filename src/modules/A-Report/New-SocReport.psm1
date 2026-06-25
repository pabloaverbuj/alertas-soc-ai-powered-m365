# A-Report/New-SocReport.psm1
# Seccion A - Informe. Render como DOCUMENTO formal (portada + metadatos + indice numerado +
# secciones jerarquicas con tablas y badges de severidad + plan de remediacion priorizado).
# Consume el objeto $Data plano (Incidents, Coverage, Identity, Endpoints, Behavior, AttackPaths,
# SignIns, Trends, DeviceCode, TrendCoverage, Hygiene, Drift) producido por el orquestador.

# ---------------------------------------------------------------------------
#  Entrada
# ---------------------------------------------------------------------------
function New-SocReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('weekly','critical')] [string] $Mode,
        [Parameter(Mandatory)][System.Collections.IDictionary] $Data,
        [object] $Settings = (Get-SocContext).Settings,
        [int]    $PeriodDays = 7,
        [object] $PrevState = $null
    )
    $now   = Get-Date
    $title = if ($Mode -eq 'weekly') { 'Geonosis SOC - Reporte de Postura y Amenazas' }
             else                    { 'Geonosis SOC - ALERTA Critica (out-of-band)' }

    # Análisis IA (si está configurada). Si no, resumen ejecutivo determinista lo arma el render.
    $exec = $null
    try { $exec = Invoke-ClaudeAnalysis -Tier 'critical' -UserPrompt (New-SocExecPrompt -Mode $Mode -Data $Data -PrevState $PrevState) } catch {}

    [pscustomobject]@{
        Title       = $title
        Mode        = $Mode
        GeneratedAt = $now.ToString('yyyy-MM-dd HH:mm')
        PeriodDays  = $PeriodDays
        Executive   = $exec
        Data        = $Data
        Remediation = (Build-SocRemediation -Data $Data)
    }
}

function Protect-SocUpn { param([string]$u) if (-not $u) { return $u } if ($u -notmatch '@') { return $u }
    $p=$u.Split('@'); $l=$p[0]; ($(if($l.Length -le 2){$l[0]+'*'}else{$l.Substring(0,2)+('*'*([Math]::Min(6,$l.Length-2)))})) + '@' + $p[1] }
function Protect-SocIp { param([string]$ip) if ($ip -match '^(\d+\.\d+\.\d+)\.\d+$') { return "$($Matches[1]).x" } $ip }

function New-SocExecPrompt {
    param([string] $Mode, [System.Collections.IDictionary] $Data, [object] $PrevState = $null)
    # Minimización: capar arrays + redacción PII opcional (settings.ai.redactPII). Azure OpenAI es del mismo tenant,
    # pero igual se reduce el volumen y se ofrece pseudonimización de UPN/IP como guardrail de gobierno.
    $redact = $false
    try { $redact = [bool](Get-SocContext).Settings.ai.redactPII } catch {}
    $fu = { param($u) if ($redact) { Protect-SocUpn $u } else { $u } }
    $fi = { param($i) if ($redact) { Protect-SocIp  $i } else { $i } }

    $payload = [ordered]@{
        Incidentes   = @($Data.Incidents.Items | Select-Object -First 25 | ForEach-Object { [ordered]@{ Id=$_.Id; Title=$_.Title; Severity=$_.Severity; Status=$_.Status; Created=$_.Created; Mitre=$_.Mitre; AlertCount=$_.AlertCount; Entities=@($_.Entities | ForEach-Object { & $fu $_ }) } })
        Cobertura    = @{ resumen=$Data.Coverage.Summary; gaps=@($Data.Coverage.Gaps.Scenario) }
        Identidad    = @{ riskyUsers=@($Data.Identity.RiskyUsers | Select-Object -First 20 | ForEach-Object { [ordered]@{ riskLevel=$_.riskLevel; userDisplayName=$_.userDisplayName; userPrincipalName=(& $fu $_.userPrincipalName); riskState=$_.riskState } }); detecciones=@($Data.Identity.Detections | Select-Object -First 15 | ForEach-Object { [ordered]@{ riskEventType=$_.riskEventType; riskLevel=$_.riskLevel; userPrincipalName=(& $fu $_.userPrincipalName) } }) }
        Endpoints    = @{ resumen=$Data.Endpoints.Summary; noncompliant=@($Data.Endpoints.IntuneGaps | Select-Object -First 20 | ForEach-Object { [ordered]@{ Name=$_.Name; User=(& $fu $_.User); Compliance=$_.Compliance; Encrypted=$_.Encrypted } }) }
        DeviceCode   = @{ signins=@($Data.DeviceCode.SignIns).Count; bloqueado=$Data.DeviceCode.Blocked; enRiesgo=$Data.DeviceCode.AtRisk }
        PasswordSpray= @{ resumen=$Data.PasswordSpray.Summary; ipsSpray=@($Data.PasswordSpray.SprayIPs | Select-Object -First 10 | ForEach-Object { [ordered]@{ IPAddress=(& $fi $_.IPAddress); Country=$_.Country; UsuariosDistintos=$_.UsuariosDistintos } }); wowFallosPassword=$Data.PasswordSpray.WoW.FallosPassword; wowUsuariosAtacados=$Data.PasswordSpray.WoW.UsuariosAtacados }
        ConfigDrift  = @($Data.Drift.Findings | Select-Object Severity,Type,Policy,Detail)
        RutasAtaque  = @{ resumen=$Data.AttackPaths.Summary; aCrownJewels=@($Data.AttackPaths.ToCrown | Select-Object Name,Impact) }
        CrownJewels  = @{ identidadesPrivilegiadas=@($Data.CrownJewels.identities | Where-Object { $_.tier -eq 0 } | ForEach-Object { & $fu $_.value }) }
        ThreatIntel  = @{ kevNuevos=@($Data.Trends.Kev | Select-Object -First 15 cveID,product,vulnerabilityName); cruceCobertura=@($Data.TrendCoverage.Findings | Select-Object Trend,Scenarios,GapCount,Total,Exposed,Mitre) }
        RiskEngine   = @{ entidadesTopRiesgo=@($Data.RiskEngine.EntityRisk | Select-Object -First 15 | ForEach-Object { [ordered]@{ Entidad=(& $fu $_.Entity); Tipo=$_.Type; Score=$_.Score; Nivel=$_.Level; Señales=$_.Signals } }); hallazgos=@($Data.RiskEngine.Findings | Select-Object Key,Type,Severity,State,Delta) }
        Postura      = $Data.Posture.Summary
        Hunting      = @{ email=$Data.Hunting.EmailPhishing.Summary; urls=$Data.Hunting.UrlClicks.Summary; oauth=$Data.Hunting.OAuthApps.Summary; priv=$Data.Hunting.PrivActivity.Summary; detalleUrlClicks=@($Data.Hunting.UrlClicks.Rows | Select-Object -First 10 AccountUpn,Url,ThreatTypes,IsClickedThrough) }
        Higiene      = $Data.Hygiene.Summary
    }
    $jsonNow  = $payload | ConvertTo-Json -Depth 8
    $jsonPrev = if ($PrevState) { ($PrevState | ConvertTo-Json -Depth 6) } else { 'null (sin línea base, primer reporte)' }
    @"
Modo del reporte: $Mode.

=== HALLAZGOS REALES DE ESTA SEMANA (JSON) ===
$jsonNow

=== ESTADO DEL REPORTE ANTERIOR (para el delta) ===
$jsonPrev

Generá el análisis completo siguiendo EXACTAMENTE la estructura de secciones indicada en tus instrucciones de sistema.
"@
}

# ---------------------------------------------------------------------------
#  Plan de remediacion priorizado (derivado de los hallazgos)
# ---------------------------------------------------------------------------
function Build-SocRemediation {
    param([System.Collections.IDictionary] $Data)
    $items = New-Object System.Collections.Generic.List[object]

    $crit = @($Data.Incidents.Critical)
    if ($crit.Count) {
        $items.Add([pscustomobject]@{ Prio='P1'; Sev='critical'; Area='Detección'
            Action='Investigar y contener incidentes críticos abiertos'
            Detail=("$($crit.Count) incidente(s) high sin resolver: " + (($crit | ForEach-Object { $_.Title }) -join '; '))
            Steps=@('Aislar dispositivos/identidades afectadas en Defender XDR.','Forzar reseteo de credenciales de los usuarios involucrados y revocar sesiones.','Buscar persistencia (reglas de reenvío, apps OAuth, tokens).','Documentar y escalar según severidad.') })
    }
    $driftHigh = @($Data.Drift.High)
    if ($driftHigh.Count) {
        $items.Add([pscustomobject]@{ Prio='P1'; Sev='high'; Area='Configuración'
            Action='Enforzar políticas de Conditional Access en report-only'
            Detail=("$($driftHigh.Count) política(s) diseñadas pero NO enforced: " + (($driftHigh | ForEach-Object { $_.Policy }) -join '; '))
            Steps=@('Revisar logs report-only por impacto (Teams Rooms / IoT / cuentas de servicio).','Crear exclusiones puntuales documentadas si hace falta.','Cambiar estado a "On" (enforced).','Validar acceso post-enforce y monitorear fallos.') })
    }
    $hru = @($Data.Identity.HighRiskUsers)
    if ($hru.Count) {
        $items.Add([pscustomobject]@{ Prio='P2'; Sev='high'; Area='Identidad'
            Action='Remediar usuarios de alto riesgo (Entra ID Protection)'
            Detail=(($hru | ForEach-Object { $_.userPrincipalName }) -join '; ')
            Steps=@('Confirmar/forzar reseteo de contraseña y MFA.','Revocar tokens de actualización (revoke sessions).','Revisar sign-ins recientes por país/IP anómalos.','Marcar el riesgo como remediado o confirmar compromiso.') })
    }
    if ($Data.DeviceCode.AtRisk) {
        $items.Add([pscustomobject]@{ Prio='P2'; Sev='high'; Area='Identidad'
            Action='Bloquear el flujo device-code (anti Kali365 / AiTM)'
            Detail='La CA que bloquea device code flow no está enforced; el tenant está expuesto a robo de token post-MFA.'
            Steps=@('Revisar SigninLogs con AuthenticationProtocol == "deviceCode" por uso legítimo.','Enforzar la CA "GLOBAL - 1020 - BLOCK - Device Code Auth Flow".','Habilitar token protection (CAD016) y MFA phishing-resistant para admins.') })
    }
    $gaps = @($Data.Coverage.Gaps)
    if ($gaps.Count) {
        $top = ($gaps | Select-Object -First 6 | ForEach-Object { $_.Scenario }) -join '; '
        $items.Add([pscustomobject]@{ Prio='P2'; Sev='medium'; Area='Cobertura'
            Action='Cerrar gaps de cobertura de detección (SOC optimization)'
            Detail=("$($gaps.Count) escenario(s) con cobertura incompleta. Top: $top")
            Steps=@('Abrir SOC optimization en el portal Defender.','Instalar las analytic rules sugeridas por cada escenario en estado Active.','Priorizar las amenazas cruzadas con tendencias reales (ver sección 4.2).') })
    }
    $ig = @($Data.Endpoints.IntuneGaps)
    if ($ig.Count) {
        $items.Add([pscustomobject]@{ Prio='P3'; Sev='medium'; Area='Endpoints'
            Action='Remediar endpoints noncompliant / sin cifrado'
            Detail=("$($ig.Count) dispositivo(s) noncompliant en Intune.")
            Steps=@('Revisar causa de incumplimiento por dispositivo.','Forzar BitLocker donde falte.','Notificar a usuarios y dar plazo de remediación.') })
    }
    # orden P1 -> P3
    $rank = @{ P1=1; P2=2; P3=3 }
    $items | Sort-Object { $rank[$_.Prio] }
}

# ---------------------------------------------------------------------------
#  Helpers de render
# ---------------------------------------------------------------------------
function ConvertTo-SocEnc { param([object]$s) if ($null -eq $s) { return '' } [System.Net.WebUtility]::HtmlEncode([string]$s) }

function New-SocBadge {
    param([string]$Sev)
    $k = ([string]$Sev).ToLower()
    $cls = switch -Regex ($k) {
        'crit|high|atrisk|active|alto'   { 'b-crit'; break }
        'medium|warn|expuesto|medio'     { 'b-med';  break }
        'low|report|bajo'                { 'b-low';  break }
        'ok|good|completed|resolved|enforced|cubierto' { 'b-ok'; break }
        default                          { 'b-info' }
    }
    "<span class='badge $cls'>$([System.Net.WebUtility]::HtmlEncode(([string]$Sev).ToUpper()))</span>"
}

function New-SocStateBadge {
    param([string]$State)
    $cls = switch -Regex (([string]$State).ToLower()) {
        'nuevo|empeor'   { 'b-crit'; break }
        'recurrente'     { 'b-med';  break }
        'mejor|resuelto' { 'b-ok';   break }
        default          { 'b-info' }
    }
    "<span class='badge $cls'>$([System.Net.WebUtility]::HtmlEncode(([string]$State).ToUpper()))</span>"
}

# Tabla generica. $Cols = @( @{H='Header'; P='Prop'} | @{H='Header'; F={ param($r) '<html>' }} )
function New-SocTable {
    param([object[]]$Items, [object[]]$Cols, [string]$Empty='Sin datos en el período.')
    $items = @($Items)
    if (-not $items.Count) { return "<p class='muted'>$([System.Net.WebUtility]::HtmlEncode($Empty))</p>" }
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append("<table><thead><tr>")
    foreach ($c in $Cols) { [void]$sb.Append("<th>$([System.Net.WebUtility]::HtmlEncode($c.H))</th>") }
    [void]$sb.Append("</tr></thead><tbody>")
    foreach ($it in $items) {
        [void]$sb.Append("<tr>")
        foreach ($c in $Cols) {
            $cell = if ($c.F) { & $c.F $it } else { ConvertTo-SocEnc ($it.$($c.P)) }
            [void]$sb.Append("<td>$cell</td>")
        }
        [void]$sb.Append("</tr>")
    }
    [void]$sb.Append("</tbody></table>")
    $sb.ToString()
}

function New-SocWowBadge {
    param($Pct)
    if ($null -eq $Pct) { return "<span class='badge b-info'>NUEVO</span>" }
    if ($Pct -gt 0) { return "<span class='badge b-crit'>&#9650; +$Pct% (peor)</span>" }
    if ($Pct -lt 0) { return "<span class='badge b-ok'>&#9660; $Pct% (mejor)</span>" }
    "<span class='badge b-info'>0% (igual)</span>"
}

function New-SocSevColor {
    param([string]$Label)
    # Paleta de marca Geonosis (sin verde: positivo = azul).
    switch -Regex (([string]$Label).ToLower()) {
        'crit|high|gap|fall|expuesto|atrisk' { '#FF6532'; break }   # Naranja 1
        'medium|med|warn'                    { '#FF9817'; break }   # Naranja 2
        'low|report'                         { '#FFC810'; break }   # Amarillo
        'ok|cubierto|exito|success|enforced|completed|mejor' { '#2965FF'; break }   # Azul 2 (positivo)
        default { '#5b6470' }
    }
}

# Barras horizontales table-based (email-safe, renderiza en Outlook).
function New-SocBarChart {
    param([string]$Title, [object[]]$Segments)   # Segments: @{Label;Value;Color}
    $segs = @($Segments | Where-Object { $_ })
    $total = ($segs | Measure-Object -Property Value -Sum).Sum; if (-not $total) { $total = 1 }
    $sb = "<div style='margin:8px 0 14px'>"
    if ($Title) { $sb += "<div style='font-size:12px;font-weight:600;color:#333;margin-bottom:5px'>$(ConvertTo-SocEnc $Title)</div>" }
    foreach ($s in $segs) {
        $pct = [math]::Round(100 * ([double]$s.Value) / $total)
        $rest = 100 - $pct
        $col = if ($s.Color) { $s.Color } else { New-SocSevColor $s.Label }
        $fill = if ($pct -gt 0) { "<td width='$pct%' bgcolor='$col' style='background:$col;height:14px;font-size:1px;line-height:14px'>&nbsp;</td>" } else { '' }
        $bg   = if ($rest -gt 0) { "<td width='$rest%' bgcolor='#edeff2' style='background:#edeff2;height:14px;font-size:1px;line-height:14px'>&nbsp;</td>" } else { '' }
        $sb += "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' style='margin:2px 0'><tr>" +
               "<td width='150' style='font-size:11.5px;color:#444'>$(ConvertTo-SocEnc $s.Label)</td>" +
               "<td><table role='presentation' width='100%' cellpadding='0' cellspacing='0'><tr>$fill$bg</tr></table></td>" +
               "<td width='80' style='font-size:11.5px;color:#444;text-align:right'>$([int]$s.Value) ($pct%)</td>" +
               "</tr></table>"
    }
    $sb + "</div>"
}

# Torta real via QuickChart (imagen hosteada). Fallback = las barras al lado.
function New-SocPie {
    param([string]$Title, [string[]]$Labels, [object[]]$Data, [string[]]$Colors)
    $cfg = @{
        type = 'doughnut'
        data = @{ labels = $Labels; datasets = @(@{ data = $Data; backgroundColor = $Colors }) }
        options = @{ plugins = @{ legend = @{ position = 'right'; labels = @{ fontSize = 11 } }; doughnutlabel = @{} } }
    } | ConvertTo-Json -Depth 8 -Compress
    $enc = [uri]::EscapeDataString($cfg)
    "<img alt='$(ConvertTo-SocEnc $Title)' width='250' height='160' style='display:block' src='https://quickchart.io/chart?bkg=white&w=250&h=160&c=$enc'>"
}

# Par torta + barras lado a lado (2 columnas).
function New-SocChartPair {
    param([string]$Title, [object[]]$Segments)
    $segs   = @($Segments | Where-Object { $_ })
    $labels = $segs | ForEach-Object { [string]$_.Label }
    $data   = $segs | ForEach-Object { [int]$_.Value }
    $colors = $segs | ForEach-Object { if ($_.Color) { $_.Color } else { New-SocSevColor $_.Label } }
    $pie  = New-SocPie -Title $Title -Labels $labels -Data $data -Colors $colors
    $bars = New-SocBarChart -Title '' -Segments $segs
    "<div style='border:1px solid #e1e4e8;border-radius:8px;padding:12px 14px;margin:10px 0;background:#fafbfc'>" +
    "<div style='font-size:13px;font-weight:600;color:#0000FF;margin-bottom:6px'>$(ConvertTo-SocEnc $Title)</div>" +
    "<table role='presentation' width='100%' cellpadding='0' cellspacing='0'><tr>" +
    "<td width='260' valign='middle'>$pie</td>" +
    "<td valign='middle' style='padding-left:14px'>$bars</td>" +
    "</tr></table></div>"
}

function New-SocList { param([string[]]$Items) if (-not @($Items).Count) { return '' } "<ul>" + (($Items | ForEach-Object { "<li>$(ConvertTo-SocEnc $_)</li>" }) -join '') + "</ul>" }

# ---------------------------------------------------------------------------
#  Render del documento completo
# ---------------------------------------------------------------------------
function ConvertTo-SocHtml {
    param([object] $Report)
    $d = $Report.Data
    $S = [System.Text.StringBuilder]::new()

    # ---- Indice (numeros fijos) ----
    $toc = @(
        '1. Análisis de seguridad (IA): dirección, observabilidad probabilística, triage y correlación',
        '1.1 Motor de riesgo: estado de hallazgos y score de entidades',
        '2. Detección',
        '2.1 Incidentes de seguridad',
        '2.2 Cobertura de detección (SOC optimization)',
        '3. Observabilidad y postura',
        '3.1 Identidad en riesgo',
        '3.2 Postura de endpoints',
        '3.3 Anomalías de comportamiento (UEBA)',
        '3.4 Rutas de ataque',
        '3.5 Telemetría de inicios de sesión',
        '3.6 Password spray (detección y tendencia semanal)',
        '3.7 Advanced Hunting (email, URLs, OAuth, actividad privilegiada)',
        '4. Inteligencia de amenazas',
        '4.1 Tendencias (CISA KEV / IOCs)',
        '4.2 Cruce tendencia vs cobertura',
        '4.3 Phishing de device-code (Kali365)',
        '5. Higiene y configuración',
        '5.1 Higiene de datos y costos',
        '5.2 Desvíos de configuración (config drift)',
        '5.3 Postura: Secure Score y Exposure Score (tendencia)',
        '6. Plan de remediación priorizado'
    )

    # =================== PORTADA / METADATOS ===================
    [void]$S.Append("<div class='coverband'><img src='cid:geologo' alt='Geonosis' width='220' style='display:block;border:0'></div>")
    [void]$S.Append("<div class='cover'>")
    [void]$S.Append("<div class='kicker'>INFORME DE SEGURIDAD &middot; CONFIDENCIAL - USO INTERNO</div>")
    [void]$S.Append("<h1>$(ConvertTo-SocEnc $Report.Title)</h1>")
    [void]$S.Append("<div class='sub'>Centro de Operaciones de Seguridad &middot; Geonosis S.A.</div>")
    [void]$S.Append("</div>")

    $kpiCrit = @($d.Incidents.Critical).Count
    $kpiHru  = @($d.Identity.HighRiskUsers).Count
    $kpiEp   = @($d.Endpoints.HighRisk).Count
    $kpiGap  = @($d.Coverage.Gaps).Count
    $kpiDr   = @($d.Drift.High).Count

    $orgName = if ($Settings.organizationName) { $Settings.organizationName } else { 'Organization' }
    $workspaceName = if ($Settings.workspace.name) { $Settings.workspace.name } else { 'Sentinel workspace' }

    [void]$S.Append("<table class='meta'><tbody>")
    [void]$S.Append("<tr><th>Organización</th><td>$(ConvertTo-SocEnc $orgName)</td><th>Generado</th><td>$(ConvertTo-SocEnc $Report.GeneratedAt) (ART)</td></tr>")
    [void]$S.Append("<tr><th>Período analizado</th><td>Últimos $($Report.PeriodDays) días</td><th>Modo</th><td>$(ConvertTo-SocEnc $Report.Mode)</td></tr>")
    [void]$S.Append("<tr><th>Fuentes</th><td colspan='3'>Microsoft Sentinel ($(ConvertTo-SocEnc $workspaceName)) &middot; Defender XDR &middot; Entra ID Protection &middot; Intune &middot; Exposure Mgmt</td></tr>")
    [void]$S.Append("<tr><th>Motor</th><td colspan='3'>Reglas/KQL deterministas + capa IA $([bool]$Report.Executive ? '(activa)' : '(no configurada)')</td></tr>")
    [void]$S.Append("</tbody></table>")

    # ---- Cuadro de severidad (KPI cards) ----
    [void]$S.Append("<div class='cards'>")
    [void]$S.Append((New-SocCard 'Incidentes críticos' $kpiCrit ($kpiCrit -gt 0)))
    [void]$S.Append((New-SocCard 'Usuarios alto riesgo' $kpiHru ($kpiHru -gt 0)))
    [void]$S.Append((New-SocCard 'Endpoints en riesgo' $kpiEp ($kpiEp -gt 0)))
    [void]$S.Append((New-SocCard 'Gaps de cobertura' $kpiGap ($kpiGap -gt 0)))
    [void]$S.Append((New-SocCard 'Drift crítico' $kpiDr ($kpiDr -gt 0)))
    [void]$S.Append("</div>")

    # ---- Panel visual (dashboard: torta QuickChart + barras CSS) ----
    [void]$S.Append("<h2 class='toc-h'>Panel visual</h2>")
    $sevSeg = @($d.Incidents.Items | Group-Object Severity | ForEach-Object { @{ Label=$_.Name; Value=$_.Count } })
    if (-not $sevSeg.Count) { $sevSeg = @(@{ Label='sin incidentes'; Value=1; Color='#2965FF' }) }
    [void]$S.Append((New-SocChartPair 'Incidentes por severidad' $sevSeg))

    $covGap = @($d.Coverage.Gaps).Count; $covTot = @($d.Coverage.Rows).Count; $covOk = [math]::Max(0, $covTot - $covGap)
    [void]$S.Append((New-SocChartPair 'Cobertura de detección: gaps vs cubierto' @(
        @{ Label='Gap (Active)'; Value=$covGap; Color='#FF6532' },
        @{ Label='Cubierto';     Value=$covOk;  Color='#2965FF' })))

    if ($d.PasswordSpray) {
        [void]$S.Append((New-SocChartPair 'Inicios de sesión: OK vs fallidos' @(
            @{ Label='OK';       Value=[int]$d.PasswordSpray.StatsCur.Exitosos; Color='#2965FF' },
            @{ Label='Fallidos'; Value=[int]$d.PasswordSpray.StatsCur.Fallidos; Color='#FF6532' })))
    }

    # =================== INDICE ===================
    [void]$S.Append("<h2 class='toc-h'>Contenido</h2><div class='toc'>")
    foreach ($t in $toc) {
        $cls = if ($t -match '^\d+\.\d') { 'toc-sub' } else { 'toc-top' }
        [void]$S.Append("<div class='$cls'>$(ConvertTo-SocEnc $t)</div>")
    }
    [void]$S.Append("</div>")

    # =================== 1. ANALISIS DE SEGURIDAD (IA) ===================
    [void]$S.Append((New-SocH 2 '1. Análisis de seguridad (IA)'))
    if ($Report.Executive) {
        [void]$S.Append("<div class='ai'>")
        [void]$S.Append((ConvertFrom-SocMarkdown $Report.Executive))
        [void]$S.Append("</div>")
    } else {
        [void]$S.Append("<p class='muted'>Capa IA no disponible en esta corrida — resumen determinista:</p>")
        [void]$S.Append((New-SocExecHtml -Data $d -Kpi @{Crit=$kpiCrit;Hru=$kpiHru;Ep=$kpiEp;Gap=$kpiGap;Dr=$kpiDr}))
    }

    # ---- 1.1 Motor de riesgo (estado de hallazgos + score por entidad) ----
    $re = $d.RiskEngine
    if ($re) {
        [void]$S.Append((New-SocH 3 '1.1 Motor de riesgo: estado de hallazgos y score de entidades'))
        [void]$S.Append("<p>$(ConvertTo-SocEnc $re.Summary)</p>")
        [void]$S.Append("<h4>Entidades por nivel de riesgo (usuario / dispositivo / IP)</h4>")
        [void]$S.Append((New-SocTable -Items (@($re.EntityRisk) | Select-Object -First 15) -Empty 'Sin entidades con riesgo acumulado.' -Cols @(
            @{H='Entidad'; P='Entity'},
            @{H='Tipo'; P='Type'},
            @{H='Score'; P='Score'},
            @{H='Nivel'; F={ param($r) New-SocBadge $r.Level }},
            @{H='Señales acumuladas'; P='Signals'}
        )))
        [void]$S.Append("<h4>Estado de hallazgos vs. reporte anterior</h4>")
        [void]$S.Append((New-SocTable -Items (@($re.Findings) | Sort-Object @{e={ @('nuevo','empeoró','recurrente','mejoró','resuelto').IndexOf($_.State) }},@{e='Score';d=$true} | Select-Object -First 40) -Empty 'Sin hallazgos.' -Cols @(
            @{H='Estado'; F={ param($r) New-SocStateBadge $r.State }},
            @{H='Tipo'; P='Type'},
            @{H='Severidad'; F={ param($r) if ($r.Severity -ne '-') { New-SocBadge $r.Severity } else { '-' } }},
            @{H='Hallazgo'; P='Title'},
            @{H='Entidad'; P='Entity'}
        )))
    }

    # =================== 2. DETECCION ===================
    [void]$S.Append((New-SocH 2 '2. Detección'))
    [void]$S.Append((New-SocH 3 '2.1 Incidentes de seguridad'))
    [void]$S.Append((New-SocTable -Items $d.Incidents.Items -Empty 'Sin incidentes en el período.' -Cols @(
        @{H='Severidad'; F={ param($r) New-SocBadge $r.Severity }},
        @{H='ID'; P='Id'},
        @{H='Título'; P='Title'},
        @{H='Estado'; P='Status'},
        @{H='Creado'; F={ param($r) ConvertTo-SocEnc (([string]$r.Created) -replace 'T',' ' -replace '\..*$','') }},
        @{H='Alertas'; P='AlertCount'},
        @{H='MITRE'; F={ param($r) ConvertTo-SocEnc (@($r.Mitre) -join ', ') }},
        @{H='Entidades'; F={ param($r) ConvertTo-SocEnc (@($r.Entities) -join ', ') }}
    )))

    [void]$S.Append((New-SocH 3 '2.2 Cobertura de detección (SOC optimization)'))
    [void]$S.Append("<p>$(ConvertTo-SocEnc $d.Coverage.Summary.Split([char]10)[0])</p>")
    [void]$S.Append((New-SocTable -Items $d.Coverage.Rows -Empty 'Sin datos de cobertura.' -Cols @(
        @{H='Escenario de amenaza'; P='Scenario'},
        @{H='Estado'; F={ param($r) New-SocBadge $r.State }},
        @{H='Gap'; F={ param($r) if ($r.Gap) { New-SocBadge 'EXPUESTO' } else { New-SocBadge 'cubierto' } }}
    )))

    # =================== 3. OBSERVABILIDAD ===================
    [void]$S.Append((New-SocH 2 '3. Observabilidad y postura'))

    [void]$S.Append((New-SocH 3 '3.1 Identidad en riesgo'))
    [void]$S.Append((New-SocTable -Items $d.Identity.RiskyUsers -Empty 'Sin usuarios en riesgo.' -Cols @(
        @{H='Nivel'; F={ param($r) New-SocBadge $r.riskLevel }},
        @{H='Usuario'; P='userDisplayName'},
        @{H='UPN'; P='userPrincipalName'},
        @{H='Estado riesgo'; P='riskState'}
    )))
    $det = @($d.Identity.Detections)
    if ($det.Count) {
        [void]$S.Append("<p class='muted'>Detecciones de riesgo recientes: $($det.Count)</p>")
        [void]$S.Append((New-SocTable -Items ($det | Select-Object -First 10) -Cols @(
            @{H='Tipo'; P='riskEventType'},
            @{H='Nivel'; F={ param($r) New-SocBadge $r.riskLevel }},
            @{H='Usuario'; P='userPrincipalName'},
            @{H='Detectado'; F={ param($r) ConvertTo-SocEnc (([string]$r.detectedDateTime) -replace 'T',' ' -replace '\..*$','') }}
        )))
    }

    [void]$S.Append((New-SocH 3 '3.2 Postura de endpoints'))
    [void]$S.Append("<p>$(ConvertTo-SocEnc $d.Endpoints.Summary)</p>")
    [void]$S.Append((New-SocTable -Items ($d.Endpoints.IntuneGaps | Select-Object -First 30) -Empty 'Sin endpoints noncompliant.' -Cols @(
        @{H='Dispositivo'; P='Name'},
        @{H='Usuario real'; P='User'},
        @{H='Enrolado por'; P='Enroll'},
        @{H='Compliance'; F={ param($r) New-SocBadge $r.Compliance }},
        @{H='Cifrado'; F={ param($r) if ($r.Encrypted) { New-SocBadge 'ok' } else { New-SocBadge 'NO' } }}
    )))

    [void]$S.Append((New-SocH 3 '3.3 Anomalías de comportamiento (UEBA)'))
    if ($d.Behavior.Enabled) {
        [void]$S.Append((New-SocTable -Items ($d.Behavior.Anomalies | Select-Object -First 15) -Cols @(
            @{H='Usuario'; P='UserName'},
            @{H='Anomalía'; P='AnomalyTemplateName'},
            @{H='Score'; P='Score'},
            @{H='Tácticas'; F={ param($r) ConvertTo-SocEnc (@($r.Tactics) -join ', ') }}
        )))
    } else {
        [void]$S.Append("<p class='muted'>UEBA sin datos. Verificar que Entity Behavior Analytics esté habilitado en Sentinel (Settings &gt; Entity behavior).</p>")
    }

    [void]$S.Append((New-SocH 3 '3.4 Rutas de ataque'))
    [void]$S.Append("<p>$(ConvertTo-SocEnc $d.AttackPaths.Summary)</p>")
    [void]$S.Append((New-SocTable -Items $d.AttackPaths.Paths -Empty 'Sin rutas de ataque detectadas (requiere Defender for Cloud / Exposure Management con datos).' -Cols @(
        @{H='Ruta'; P='Name'},
        @{H='Impacto potencial'; P='Impact'},
        @{H='Crown jewel'; F={ param($r) if ($r.ToCrown) { New-SocBadge 'crit' } else { '-' } }}
    )))

    [void]$S.Append((New-SocH 3 '3.5 Telemetría de inicios de sesión'))
    [void]$S.Append("<p>$(ConvertTo-SocEnc $d.SignIns.Summary)</p>")
    [void]$S.Append((New-SocTable -Items ($d.SignIns.NewLocations | Select-Object -First 15) -Empty 'Sin locaciones nuevas.' -Cols @(
        @{H='Usuario'; P='UserPrincipalName'},
        @{H='País nuevo'; P='Country'},
        @{H='Primera vez'; F={ param($r) ConvertTo-SocEnc (([string]$r.FirstSeen) -replace 'T',' ' -replace '\..*$','') }}
    )))

    [void]$S.Append((New-SocH 3 '3.6 Password spray (detección y tendencia semanal)'))
    $ps = $d.PasswordSpray
    if ($ps) {
        [void]$S.Append("<p>$(ConvertTo-SocEnc $ps.Summary)</p>")
        [void]$S.Append((New-SocChartPair 'Inicios de sesión esta semana: OK vs fallidos' @(
            @{ Label='OK';       Value=[int]$ps.StatsCur.Exitosos; Color='#2965FF' },
            @{ Label='Fallidos'; Value=[int]$ps.StatsCur.Fallidos; Color='#FF6532' })))
        [void]$S.Append((New-SocBarChart 'Fallos de credencial (50126): esta semana vs anterior' @(
            @{ Label='Esta semana';     Value=[int]$ps.StatsCur.FallosPassword;  Color='#FF6532' },
            @{ Label='Semana anterior'; Value=[int]$ps.StatsPrev.FallosPassword; Color='#5b6470' })))
        $wowRows = @(
            [pscustomobject]@{ Metrica='Sign-ins fallidos';            Sem=$ps.StatsCur.Fallidos;       Ant=$ps.StatsPrev.Fallidos;       Var=$ps.WoW.Fallidos },
            [pscustomobject]@{ Metrica='Fallos de credencial (50126)'; Sem=$ps.StatsCur.FallosPassword; Ant=$ps.StatsPrev.FallosPassword; Var=$ps.WoW.FallosPassword },
            [pscustomobject]@{ Metrica='Usuarios atacados';            Sem=$ps.StatsCur.UsuariosAtacados;Ant=$ps.StatsPrev.UsuariosAtacados;Var=$ps.WoW.UsuariosAtacados },
            [pscustomobject]@{ Metrica='IPs origen (50126)';           Sem=$ps.StatsCur.IPsOrigen;      Ant=$ps.StatsPrev.IPsOrigen;      Var=$ps.WoW.IPsOrigen }
        )
        [void]$S.Append((New-SocTable -Items $wowRows -Cols @(
            @{H='Métrica'; P='Metrica'},
            @{H='Esta semana';     F={ param($r) ConvertTo-SocEnc ([int]$r.Sem) }},
            @{H='Semana anterior'; F={ param($r) ConvertTo-SocEnc ([int]$r.Ant) }},
            @{H='Variación (WoW)';  F={ param($r) New-SocWowBadge $r.Var }}
        )))
        [void]$S.Append("<h4>IPs origen de password spray</h4>")
        [void]$S.Append((New-SocTable -Items $ps.SprayIPs -Empty 'Sin IPs con patrón de spray (1 IP fallando contra muchos usuarios).' -Cols @(
            @{H='IP'; P='IPAddress'},
            @{H='País'; P='Country'},
            @{H='Intentos'; P='Intentos'},
            @{H='Usuarios distintos'; P='UsuariosDistintos'}
        )))
        [void]$S.Append("<h4>Sign-ins fallidos (detalle de los que NO verificaron)</h4>")
        [void]$S.Append((New-SocTable -Items ($ps.Detail | Select-Object -First 40) -Empty 'Sin sign-ins fallidos en el período.' -Cols @(
            @{H='Usuario'; P='UserPrincipalName'},
            @{H='Código'; P='ResultType'},
            @{H='Motivo del fallo'; P='ResultDescription'},
            @{H='País'; P='Country'},
            @{H='Ciudad'; P='City'},
            @{H='IP'; P='IPAddress'},
            @{H='Dispositivo'; P='Device'},
            @{H='Intentos'; P='Intentos'}
        )))
    } else {
        [void]$S.Append("<p class='muted'>Sin datos de password spray.</p>")
    }

    [void]$S.Append((New-SocH 3 '3.7 Advanced Hunting (Defender XDR)'))
    $hg = $d.Hunting
    if ($hg) {
        [void]$S.Append("<h4>Email phishing / malware</h4>")
        [void]$S.Append("<p class='muted'>$(ConvertTo-SocEnc $hg.EmailPhishing.Summary)</p>")
        [void]$S.Append((New-SocTable -Items (@($hg.EmailPhishing.Rows) | Select-Object -First 20) -Empty 'Sin datos.' -Cols @(
            @{H='Destinatario'; P='RecipientEmailAddress'}, @{H='Amenaza'; P='ThreatTypes'}, @{H='Emails'; P='Emails'}, @{H='Entregados'; P='Entregados'})))
        [void]$S.Append("<h4>Clicks a URLs maliciosas</h4>")
        [void]$S.Append("<p class='muted'>$(ConvertTo-SocEnc $hg.UrlClicks.Summary)</p>")
        [void]$S.Append((New-SocTable -Items (@($hg.UrlClicks.Rows) | Select-Object -First 20) -Empty 'Sin datos.' -Cols @(
            @{H='Usuario'; P='AccountUpn'}, @{H='URL'; P='Url'}, @{H='Amenaza'; P='ThreatTypes'},
            @{H='Pasó advertencia'; F={ param($r) if ($r.IsClickedThrough -eq 1) { New-SocBadge 'crit' } else { '-' } }})))
        [void]$S.Append("<h4>Apps OAuth (consents recientes)</h4>")
        [void]$S.Append("<p class='muted'>$(ConvertTo-SocEnc $hg.OAuthApps.Summary)</p>")
        [void]$S.Append((New-SocTable -Items (@($hg.OAuthApps.Rows) | Select-Object -First 20) -Empty 'Sin consents en el período.' -Cols @(
            @{H='Fecha'; P='Fecha'}, @{H='App'; P='App'}, @{H='Quién consintió'; P='Quien'}, @{H='Acción'; P='Accion'})))
        [void]$S.Append("<h4>Actividad en roles privilegiados</h4>")
        [void]$S.Append("<p class='muted'>$(ConvertTo-SocEnc $hg.PrivActivity.Summary)</p>")
        [void]$S.Append((New-SocTable -Items (@($hg.PrivActivity.Rows) | Select-Object -First 20) -Empty 'Sin cambios en el período.' -Cols @(
            @{H='Fecha'; P='Fecha'}, @{H='Rol'; P='Rol'}, @{H='Usuario'; P='Target'}, @{H='Por'; P='Quien'})))
    } else { [void]$S.Append("<p class='muted'>Sin datos de Advanced Hunting.</p>") }

    # =================== 4. THREAT INTEL ===================
    [void]$S.Append((New-SocH 2 '4. Inteligencia de amenazas'))
    [void]$S.Append((New-SocH 3 '4.1 Tendencias (CISA KEV / IOCs)'))
    [void]$S.Append("<p>$(ConvertTo-SocEnc $d.Trends.Summary)</p>")
    [void]$S.Append((New-SocTable -Items ($d.Trends.Kev | Select-Object -First 15) -Empty 'Sin KEV nuevos.' -Cols @(
        @{H='CVE'; P='cveID'},
        @{H='Vendor'; P='vendorProject'},
        @{H='Producto'; P='product'},
        @{H='Vulnerabilidad'; P='vulnerabilityName'},
        @{H='Agregado'; P='dateAdded'}
    )))

    [void]$S.Append((New-SocH 3 '4.2 Cruce tendencia vs cobertura'))
    [void]$S.Append((New-SocTable -Items $d.TrendCoverage.Findings -Empty 'Sin cruce disponible.' -Cols @(
        @{H='Tendencia (mundo real)'; P='Trend'},
        @{H='Escenarios de cobertura'; P='Scenarios'},
        @{H='Gaps'; F={ param($r) ConvertTo-SocEnc ("$($r.GapCount)/$($r.Total)") }},
        @{H='MITRE'; P='Mitre'},
        @{H='Estado'; F={ param($r) if ($r.Exposed) { New-SocBadge 'EXPUESTO' } else { New-SocBadge 'ok' } }}
    )))

    [void]$S.Append((New-SocH 3 '4.3 Phishing de device-code (Kali365)'))
    $dcRows = @([pscustomobject]@{
        Signins = @($d.DeviceCode.SignIns).Count
        Bloqueo = if ($d.DeviceCode.Blocked) { 'enforced' } else { 'NO enforced' }
        Estado  = if ($d.DeviceCode.AtRisk) { 'EXPUESTO' } else { 'ok' }
    })
    [void]$S.Append((New-SocTable -Items $dcRows -Cols @(
        @{H='Sign-ins deviceCode'; P='Signins'},
        @{H='Bloqueo CA'; F={ param($r) New-SocBadge $r.Bloqueo }},
        @{H='Estado'; F={ param($r) New-SocBadge $r.Estado }}
    )))

    # =================== 5. HIGIENE ===================
    [void]$S.Append((New-SocH 2 '5. Higiene y configuración'))
    [void]$S.Append((New-SocH 3 '5.1 Higiene de datos y costos'))
    [void]$S.Append("<p>$(ConvertTo-SocEnc $d.Hygiene.Summary)</p>")
    [void]$S.Append((New-SocTable -Items ($d.Hygiene.TopCost | Select-Object -First 10) -Empty 'Sin datos de ingesta.' -Cols @(
        @{H='Tabla'; P='DataType'},
        @{H='GB (período)'; P='GB'}
    )))

    [void]$S.Append((New-SocH 3 '5.2 Desvíos de configuración (config drift)'))
    [void]$S.Append((New-SocTable -Items $d.Drift.Findings -Empty 'Sin desvíos detectados.' -Cols @(
        @{H='Severidad'; F={ param($r) New-SocBadge $r.Severity }},
        @{H='Tipo'; P='Type'},
        @{H='Política'; P='Policy'},
        @{H='Detalle'; P='Detail'}
    )))

    [void]$S.Append((New-SocH 3 '5.3 Postura: Secure Score y Exposure Score (tendencia)'))
    if ($d.Posture) {
        $pst = $d.Posture
        $rows = @()
        if ($pst.Secure) { $rows += [pscustomobject]@{ M='Microsoft Secure Score'; V="$($pst.Secure.Pct)% ($($pst.Secure.Current)/$($pst.Secure.Max))"; D=$pst.SecureDelta; Good='up' } }
        if ($null -ne $pst.Exposure) { $rows += [pscustomobject]@{ M='Defender Exposure Score'; V="$($pst.Exposure)"; D=$pst.ExposureDelta; Good='down' } }
        [void]$S.Append((New-SocTable -Items $rows -Empty 'Sin datos de postura (requiere SecurityEvents.Read.All / Defender).' -Cols @(
            @{H='Métrica'; P='M'},
            @{H='Valor'; P='V'},
            @{H='Δ vs anterior'; F={ param($r)
                if ($null -eq $r.D) { return "<span class='badge b-info'>NUEVO</span>" }
                $better = ($r.Good -eq 'up' -and $r.D -ge 0) -or ($r.Good -eq 'down' -and $r.D -le 0)
                $cls = if ($r.D -eq 0) { 'b-info' } elseif ($better) { 'b-ok' } else { 'b-crit' }
                $sign = if ($r.D -ge 0) { '+' } else { '' }
                "<span class='badge $cls'>$sign$($r.D)</span>" }}
        )))
    } else { [void]$S.Append("<p class='muted'>Sin datos de postura.</p>") }

    # =================== 6. REMEDIACION ===================
    [void]$S.Append((New-SocH 2 '6. Plan de remediación priorizado'))
    $rem = @($Report.Remediation)
    if (-not $rem.Count) {
        [void]$S.Append("<p class='muted'>Sin acciones de remediación pendientes este período.</p>")
    } else {
        foreach ($r in $rem) {
            [void]$S.Append("<div class='rem'>")
            [void]$S.Append("<div class='rem-h'>$(New-SocBadge $r.Prio) $(New-SocBadge $r.Sev) <span class='rem-area'>$(ConvertTo-SocEnc $r.Area)</span> &mdash; $(ConvertTo-SocEnc $r.Action)</div>")
            [void]$S.Append("<div class='rem-d'>$(ConvertTo-SocEnc $r.Detail)</div>")
            [void]$S.Append((New-SocList $r.Steps))
            [void]$S.Append("</div>")
        }
    }

    # ---- documento ----
    return (Get-SocHtmlShell -Title $Report.Title -Generated $Report.GeneratedAt -Body $S.ToString())
}

function New-SocH { param([int]$Level,[string]$Text) "<h$Level id='s$([regex]::Replace($Text,'[^0-9]',''))'>$(ConvertTo-SocEnc $Text)</h$Level>" }

function New-SocCard {
    param([string]$Label,[int]$Value,[bool]$Alert)
    $cls = if ($Alert) { 'card card-alert' } else { 'card' }
    "<div class='$cls'><div class='card-v'>$Value</div><div class='card-l'>$(ConvertTo-SocEnc $Label)</div></div>"
}

function New-SocExecHtml {
    param([System.Collections.IDictionary]$Data, [hashtable]$Kpi)
    $bullets = New-Object System.Collections.Generic.List[string]
    if ($Kpi.Crit -gt 0) { $bullets.Add("Hay $($Kpi.Crit) incidente(s) crítico(s) abierto(s) que requieren contención inmediata.") }
    if ($Data.Drift.High) { $bullets.Add("$(@($Data.Drift.High).Count) control(es) de Conditional Access están en report-only (no protegen): incluye MFA y/o bloqueo device-code.") }
    if ($Kpi.Hru -gt 0) { $bullets.Add("$($Kpi.Hru) usuario(s) marcados de alto riesgo por Entra ID Protection.") }
    if ($Data.DeviceCode.AtRisk) { $bullets.Add("El flujo device-code NO está bloqueado: exposición directa a phishing tipo Kali365 (robo de token post-MFA).") }
    if ($Kpi.Gap -gt 0) { $bullets.Add("$($Kpi.Gap) escenario(s) de amenaza con cobertura de detección incompleta.") }
    if ($Kpi.Ep -gt 0) { $bullets.Add("$($Kpi.Ep) endpoint(s) con riesgo/exposición alta.") }
    $p = "Durante el período analizado, la postura de seguridad de Geonosis presenta los siguientes puntos salientes. El detalle por dominio está en las secciones 2 a 5 y las acciones concretas, priorizadas en la sección 6."
    "<p>$(ConvertTo-SocEnc $p)</p>" + (New-SocList $bullets.ToArray())
}

function ConvertFrom-SocInline { param([string]$s)
    $h = ConvertTo-SocEnc $s
    [regex]::Replace($h, '\*\*(.+?)\*\*', '<strong>$1</strong>')
}

function ConvertFrom-SocMarkdown {
    param([string]$Md)
    if (-not $Md) { return '' }
    $lines = ($Md -replace "`r","") -split "`n"
    $out = New-Object System.Collections.Generic.List[string]
    $i = 0
    while ($i -lt $lines.Count) {
        $l = $lines[$i].TrimEnd()
        # --- tabla markdown (| col | col | seguida de | --- | ---) ---
        if ($l -match '^\s*\|.*\|\s*$' -and ($i+1) -lt $lines.Count -and $lines[$i+1] -match '^\s*\|[\s:\-\|]+\|\s*$') {
            $hdr = ($l.Trim('| ') -split '\s*\|\s*')
            $i += 2
            $rows = New-Object System.Collections.Generic.List[object]
            while ($i -lt $lines.Count -and $lines[$i] -match '^\s*\|.*\|\s*$') {
                $rows.Add(($lines[$i].Trim('| ') -split '\s*\|\s*')); $i++
            }
            $t = "<table><thead><tr>" + (($hdr | ForEach-Object { "<th>$(ConvertFrom-SocInline $_)</th>" }) -join '') + "</tr></thead><tbody>"
            foreach ($r in $rows) { $t += "<tr>" + (($r | ForEach-Object { "<td>$(ConvertFrom-SocInline $_)</td>" }) -join '') + "</tr>" }
            $t += "</tbody></table>"
            $out.Add($t); continue
        }
        # --- encabezados ---
        if ($l -match '^\s*###\s*(.+)$')  { $out.Add("<h4>$(ConvertFrom-SocInline $Matches[1])</h4>"); $i++; continue }
        if ($l -match '^\s*##\s*(.+)$')   { $out.Add("<h3>$(ConvertFrom-SocInline $Matches[1])</h3>"); $i++; continue }
        if ($l -match '^\s*#\s*(.+)$')    { $out.Add("<h3>$(ConvertFrom-SocInline $Matches[1])</h3>"); $i++; continue }
        # --- lista ordenada ---
        if ($l -match '^\s*\d+\.\s+(.+)$') {
            $li = New-Object System.Collections.Generic.List[string]
            while ($i -lt $lines.Count -and $lines[$i] -match '^\s*\d+\.\s+(.+)$') { $li.Add("<li>$(ConvertFrom-SocInline $Matches[1])</li>"); $i++ }
            $out.Add("<ol>" + ($li -join '') + "</ol>"); continue
        }
        # --- lista no ordenada ---
        if ($l -match '^\s*[-*]\s+(.+)$') {
            $li = New-Object System.Collections.Generic.List[string]
            while ($i -lt $lines.Count -and $lines[$i] -match '^\s*[-*]\s+(.+)$') { $li.Add("<li>$(ConvertFrom-SocInline $Matches[1])</li>"); $i++ }
            $out.Add("<ul>" + ($li -join '') + "</ul>"); continue
        }
        # --- párrafo / vacío ---
        if ($l.Trim().Length -gt 0) { $out.Add("<p>$(ConvertFrom-SocInline $l)</p>") }
        $i++
    }
    ($out -join '')
}

function Get-SocHtmlShell {
    param([string]$Title,[string]$Generated,[string]$Body)
@"
<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
 body{font-family:'Inter Tight','Segoe UI',Calibri,Arial,sans-serif;color:#2D2F31;background:#EFEFEF;margin:0;padding:0;font-size:13.5px;line-height:1.5}
 .doc{max-width:900px;margin:0 auto;background:#fff;padding:40px 48px;box-shadow:0 0 0 1px #e5e7eb}
 .coverband{background:#2D2F31;padding:18px 48px;margin:-40px -48px 18px -48px}
 .cover{border-bottom:4px solid #0000FF;padding-bottom:14px;margin-bottom:18px}
 .logo{font-weight:800;font-size:24px;letter-spacing:-.5px;color:#2D2F31;margin-bottom:10px}
 .logo .o{color:#0000FF}
 .logo .tag{font-family:'Roboto Mono',Consolas,monospace;font-weight:500;font-size:12px;color:#2D2F31;letter-spacing:0;margin-left:8px}
 .logo .tag .k{color:#0000FF}
 .kicker{font-size:11px;letter-spacing:.12em;color:#0000FF;font-weight:700;margin-bottom:6px}
 h1{font-size:26px;margin:4px 0 2px;color:#2D2F31;line-height:1.2}
 .sub{color:#555;font-size:13px}
 h2{font-size:18px;color:#0000FF;margin:30px 0 8px;padding-bottom:5px;border-bottom:2px solid #cfe0ff}
 h3{font-size:15px;color:#2D2F31;margin:20px 0 6px;border-left:4px solid #0000FF;padding-left:9px}
 h4{font-size:13.5px;margin:12px 0 4px;color:#333}
 p{margin:7px 0}
 .muted{color:#6b7280;font-size:12.5px}
 table{border-collapse:collapse;width:100%;margin:10px 0;font-size:12.5px}
 th,td{border:1px solid #e1e4e8;padding:7px 9px;text-align:left;vertical-align:top}
 thead th{background:#2D2F31;color:#fff;font-weight:600;font-size:12px;letter-spacing:.02em}
 tbody tr:nth-child(even){background:#f5f7ff}
 table.meta th{background:#eaf0ff;color:#2D2F31;width:140px;white-space:nowrap}
 table.meta td{width:auto}
 .cards{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}
 .card{flex:1;min-width:120px;border:1px solid #d8def0;border-radius:8px;padding:12px 14px;text-align:center;background:#f5f7ff}
 .card-alert{border-color:#ffc7b3;background:#ffe9e1}
 .card-v{font-size:26px;font-weight:700;color:#2D2F31}
 .card-alert .card-v{color:#FF6532}
 .card-l{font-size:11px;color:#555;margin-top:2px}
 .toc-h{border:none;color:#2D2F31;font-size:16px}
 .toc{background:#f5f7ff;border:1px solid #d8def0;border-radius:8px;padding:12px 18px;margin:6px 0 4px}
 .toc-top{font-weight:600;margin:5px 0 1px}
 .toc-sub{color:#555;margin-left:18px;font-size:12.5px}
 .badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:10.5px;font-weight:700;letter-spacing:.03em}
 .b-crit{background:#ffe0d6;color:#c23e15}.b-med{background:#ffe9cc;color:#a55e00}
 .b-low{background:#fff3c4;color:#8a6d00}.b-ok{background:#e0e8ff;color:#0a33cc}.b-info{background:#e7eaee;color:#3a3f44}
 .rem{border:1px solid #e1e4e8;border-left:4px solid #0000FF;border-radius:6px;padding:11px 14px;margin:10px 0;background:#f5f7ff}
 .rem-h{font-weight:600;font-size:13.5px;margin-bottom:3px}
 .rem-area{color:#0000FF;font-size:11px;letter-spacing:.05em;text-transform:uppercase}
 .rem-d{color:#444;font-size:12.5px;margin:3px 0}
 ul{margin:6px 0 6px 4px;padding-left:20px}li{margin:2px 0}
 .footer{margin-top:34px;color:#5b6470;font-size:11px;border-top:1px solid #e1e4e8;padding-top:10px}
</style></head><body><div class="doc">
$Body
<div class="footer">Geonosis SOC AI powered &middot; generado automáticamente vía Azure Automation (Managed Identity) &middot; $([System.Net.WebUtility]::HtmlEncode($Generated)) &middot; Documento confidencial - no responder a este correo.</div>
</div></body></html>
"@
}

# ---------------------------------------------------------------------------
#  Entrega
# ---------------------------------------------------------------------------
function Publish-SocReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object] $Report, [object] $Settings = (Get-SocContext).Settings)
    $html = ConvertTo-SocHtml -Report $Report
    if ($Settings.delivery.teams.enabled) { Send-SocTeams -Report $Report -Settings $Settings }
    if ($Settings.delivery.email.enabled) { Send-SocEmail -Report $Report -Html $html -Settings $Settings }
}

function Send-SocTeams {
    param([object] $Report, [object] $Settings)
    $webhook = Get-SocSecret -Name $Settings.delivery.teams.webhookVariable
    if (-not $webhook) { Write-Warning "[teams] Sin webhook configurado."; return }
    $rem = @($Report.Remediation)
    $facts = New-Object System.Collections.Generic.List[object]
    foreach ($r in ($rem | Select-Object -First 5)) {
        $facts.Add(@{ title = "$($r.Prio) $($r.Area)"; value = $r.Action })
    }
    $d = $Report.Data
    $head = "Incidentes críticos: $(@($d.Incidents.Critical).Count) · Usuarios alto riesgo: $(@($d.Identity.HighRiskUsers).Count) · Gaps cobertura: $(@($d.Coverage.Gaps).Count) · Drift crítico: $(@($d.Drift.High).Count)"
    $body = @(
        @{ type='TextBlock'; size='Large'; weight='Bolder'; text=$Report.Title; wrap=$true },
        @{ type='TextBlock'; isSubtle=$true; text="Generado: $($Report.GeneratedAt) (ART) · Detalle completo por email"; wrap=$true; spacing='None' },
        @{ type='TextBlock'; wrap=$true; weight='Bolder'; text=$head; color='Attention' }
    )
    if ($facts.Count) { $body += @{ type='FactSet'; facts=$facts } }
    $card = @{ type='message'; attachments=@(@{ contentType='application/vnd.microsoft.card.adaptive'
        content=@{ '$schema'='http://adaptivecards.io/schemas/adaptive-card.json'; type='AdaptiveCard'; version='1.4'; body=$body } }) }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes(($card | ConvertTo-Json -Depth 20))
    Invoke-RestMethod -Method Post -Uri $webhook -ContentType 'application/json; charset=utf-8' -Body $bytes | Out-Null
    Write-Output "[teams] Enviado."
}

function Send-SocEmail {
    param([object] $Report, [string] $Html, [object] $Settings)
    # Logo oficial como adjunto inline (cid:geologo) - base64 en Automation Variable. CID porque Outlook no renderiza data-URI.
    $logo = Get-SocSecret -Name 'GeonosisSocAi-LogoB64'
    $attachments = @()
    if ($logo) {
        $attachments = @(@{
            '@odata.type' = '#microsoft.graph.fileAttachment'
            name          = 'geologo.png'; contentType = 'image/png'
            contentBytes  = $logo; isInline = $true; contentId = 'geologo'
        })
    }
    $mail = @{
        message = @{
            subject = $Report.Title
            body    = @{ contentType = 'HTML'; content = $Html }
            toRecipients = @($Settings.delivery.email.to | ForEach-Object { @{ emailAddress = @{ address = $_ } } })
            attachments  = $attachments
        }
        saveToSentItems = $false
    }
    Invoke-SocGraph -Method POST -Path "/users/$($Settings.delivery.email.from)/sendMail" -Body $mail | Out-Null
    Write-Output "[email] Enviado a $($Settings.delivery.email.to -join ', ')."
}

# ---------------------------------------------------------------------------
#  Tickets / evidencia (#9) — lista a Teams + estado persistente
# ---------------------------------------------------------------------------
function Get-SocStableId {
    param([string]$Text)
    $md5 = [System.Security.Cryptography.MD5]::Create()
    ([BitConverter]::ToString($md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))) -replace '-','').Substring(0,8)
}

function Build-SocTickets {
    # Deriva tickets del plan de remediación. Carga estado/owner/due/firstSeen del set previo por Id estable.
    param([object] $Report, [object] $PrevTickets)
    $prev = @{}; foreach ($t in @($PrevTickets)) { if ($t.Id) { $prev[$t.Id] = $t } }
    $today   = Get-Date
    $dueDays = @{ P1 = 3; P2 = 7; P3 = 14 }
    $cur = @()
    foreach ($r in @($Report.Remediation)) {
        $id = Get-SocStableId "$($r.Prio)|$($r.Area)|$($r.Action)"
        $p  = $prev[$id]
        $cur += [pscustomobject]@{
            Id        = $id
            Prio      = $r.Prio
            Sev       = $r.Sev
            Area      = $r.Area
            Action    = $r.Action
            Detail    = $r.Detail
            Owner     = if ($p -and $p.Owner) { $p.Owner } elseif ($Settings.delivery.email.to) { @($Settings.delivery.email.to)[0] } else { 'soc-owner@example.com' }
            Due       = if ($p -and $p.Due)   { $p.Due }   else { $today.AddDays($dueDays[$r.Prio]).ToString('yyyy-MM-dd') }
            State     = if ($p -and $p.State) { $p.State } else { 'abierto' }
            FirstSeen = if ($p -and $p.FirstSeen) { $p.FirstSeen } else { $today.ToString('yyyy-MM-dd') }
        }
    }
    # tickets previos que ya no están en remediación -> mitigado (se muestran una vez)
    $curIds = @($cur.Id)
    foreach ($k in $prev.Keys) {
        if ($k -notin $curIds -and $prev[$k].State -ne 'mitigado') {
            $m = $prev[$k]; $m.State = 'mitigado'; $cur += $m
        }
    }
    $cur
}

function Send-SocTeamsTickets {
    param([object[]] $Tickets, [object] $Settings)
    $webhook = Get-SocSecret -Name $Settings.delivery.teams.webhookVariable
    if (-not $webhook) { Write-Warning "[tickets] Sin webhook."; return }
    $tk = @($Tickets)
    $emoji = @{ P1='🔴'; P2='🟠'; P3='🟡' }
    $body = @(
        @{ type='TextBlock'; size='Large'; weight='Bolder'; text="🎫 Tickets SOC — $(@($tk | Where-Object {$_.State -ne 'mitigado'}).Count) abiertos"; wrap=$true }
        @{ type='TextBlock'; isSubtle=$true; spacing='None'; wrap=$true; text="Generado $((Get-Date).ToString('yyyy-MM-dd HH:mm')) ART · estado persistente" }
    )
    foreach ($t in ($tk | Sort-Object { @('P1','P2','P3').IndexOf($_.Prio) })) {
        $e = $emoji[$t.Prio]; if (-not $e) { $e='⚪' }
        $body += @{ type='TextBlock'; wrap=$true; text="$e **$($t.Prio) · $($t.Area)** — $($t.Action)" }
        $body += @{ type='TextBlock'; isSubtle=$true; spacing='None'; wrap=$true; text="estado: $($t.State) · owner: $($t.Owner) · vence: $($t.Due) · desde: $($t.FirstSeen) · #$($t.Id)" }
    }
    $card = @{ type='message'; attachments=@(@{ contentType='application/vnd.microsoft.card.adaptive'
        content=@{ '$schema'='http://adaptivecards.io/schemas/adaptive-card.json'; type='AdaptiveCard'; version='1.4'; body=$body } }) }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes(($card | ConvertTo-Json -Depth 20))
    Invoke-RestMethod -Method Post -Uri $webhook -ContentType 'application/json; charset=utf-8' -Body $bytes | Out-Null
    Write-Output "[tickets] Lista enviada a Teams ($(@($tk).Count) tickets)."
}

Export-ModuleMember -Function New-SocReport, Publish-SocReport, ConvertTo-SocHtml, Build-SocRemediation, Build-SocTickets, Send-SocTeamsTickets

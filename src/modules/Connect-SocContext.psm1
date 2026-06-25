# Connect-SocContext.psm1
# Contexto de ejecución del runbook: auth por Managed Identity + helpers para consultar
# Log Analytics (Sentinel), Microsoft Graph y ARM. Sin credenciales en código.

$script:Ctx = $null

function Connect-SocContext {
    [CmdletBinding()]
    param(
        [string] $SettingsPath = "$PSScriptRoot/../../config/settings.json"
    )
    Write-Output "[ctx] Autenticando con Managed Identity..."
    # En Azure Automation la MI se resuelve sola; localmente cae a Connect-AzAccount interactivo.
    if (-not (Get-AzContext)) { Connect-AzAccount -Identity | Out-Null }

    # Local: archivo. En Azure Automation (sin filesystem, $PSScriptRoot vacío): Automation Variable.
    # Test-Path con -LiteralPath + SilentlyContinue para que una ruta inválida no tire terminating.
    $hasFile = $SettingsPath -and [System.IO.File]::Exists($SettingsPath)   # nunca tira ante path inválido
    $json = if ($hasFile) { Get-Content -LiteralPath $SettingsPath -Raw } else { Get-SocSecret -Name 'GeonosisSocAi-Settings' }
    if (-not $json) { throw "No hay settings (ni archivo $SettingsPath ni variable GeonosisSocAi-Settings)." }
    $settings = $json | ConvertFrom-Json
    $script:Ctx = [pscustomobject]@{
        Settings    = $settings
        TenantId    = $settings.tenantId
        WorkspaceId = $settings.workspace.workspaceId
        Tokens      = @{}     # cache de tokens por recurso
    }
    return $script:Ctx
}

function Get-SocContext {
    if (-not $script:Ctx) { throw "Contexto no inicializado. Llamá Connect-SocContext primero." }
    return $script:Ctx
}

function Get-SocToken {
    param([Parameter(Mandatory)][string] $ResourceUrl)
    $ctx = Get-SocContext
    if (-not $ctx.Tokens[$ResourceUrl] -or $ctx.Tokens[$ResourceUrl].Expires -lt (Get-Date).AddMinutes(5)) {
        $t = Get-AzAccessToken -ResourceUrl $ResourceUrl
        # Az.Accounts >= 5 devuelve .Token como SecureString. Normalizar a texto plano para el header Bearer.
        $plain = if ($t.Token -is [securestring]) {
            [System.Net.NetworkCredential]::new('', $t.Token).Password
        } else { $t.Token }
        $ctx.Tokens[$ResourceUrl] = [pscustomobject]@{ Token = $plain; Expires = $t.ExpiresOn.LocalDateTime }
    }
    return $ctx.Tokens[$ResourceUrl].Token
}

# --- Log Analytics / Sentinel (KQL) -----------------------------------------
function Invoke-SocKql {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Query,
        [int] $TimespanDays = 7
    )
    $ctx   = Get-SocContext
    $token = Get-SocToken -ResourceUrl 'https://api.loganalytics.io'
    $uri   = "https://api.loganalytics.io/v1/workspaces/$($ctx.WorkspaceId)/query"
    $body  = @{ query = $Query; timespan = "P$($TimespanDays)D" } | ConvertTo-Json
    $resp  = Invoke-RestMethod -Method Post -Uri $uri -Headers @{ Authorization = "Bearer $token" } `
                               -ContentType 'application/json' -Body $body
    return ConvertFrom-SocTable $resp
}

function ConvertFrom-SocTable {
    param($Response)
    if (-not $Response.tables) { return @() }
    $t = $Response.tables[0]
    # @() fuerza array: con UNA sola columna, $t.columns.name colapsa a string escalar y $cols[$i]
    # indexaría el string carácter-por-carácter (propiedad 'V' en vez de 'Val'). Rompe queries de 1 columna.
    $cols = @($t.columns.name)
    foreach ($row in $t.rows) {
        $o = [ordered]@{}
        for ($i = 0; $i -lt $cols.Count; $i++) { $o[$cols[$i]] = $row[$i] }
        [pscustomobject]$o
    }
}

# --- Microsoft Graph ---------------------------------------------------------
function Invoke-SocGraph {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Path,        # ej: /security/incidents
        [string] $Method = 'GET',
        [string] $Version = 'v1.0',
        $Body
    )
    $token = Get-SocToken -ResourceUrl 'https://graph.microsoft.com'
    $uri   = "https://graph.microsoft.com/$Version$Path"
    $req   = @{ Method = $Method; Uri = $uri; Headers = @{ Authorization = "Bearer $token" } }
    # Body como bytes UTF-8 explícitos: evita que Invoke-RestMethod mande acentos/símbolos mal (mojibake en el mail).
    if ($Body) { $req.ContentType = 'application/json; charset=utf-8'; $req.Body = [System.Text.Encoding]::UTF8.GetBytes(($Body | ConvertTo-Json -Depth 12)) }
    $out = @()
    do {
        $resp = Invoke-RestMethod @req
        if ($resp.value) { $out += $resp.value } else { $out += $resp }
        $req.Uri = $resp.'@odata.nextLink'; $req.Remove('Body')
    } while ($req.Uri)
    return $out
}

# --- ARM (Sentinel mgmt / SOC optimization / Exposure Mgmt) ------------------
function Invoke-SocArm {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Path,        # ruta relativa a management.azure.com
        [string] $ApiVersion,
        [string] $Method = 'GET',
        $Body
    )
    $token = Get-SocToken -ResourceUrl 'https://management.azure.com'
    $uri   = "https://management.azure.com$Path" + ($(if ($ApiVersion) { "?api-version=$ApiVersion" }))
    $req   = @{ Method = $Method; Uri = $uri; Headers = @{ Authorization = "Bearer $token" } }
    if ($Body) { $req.ContentType = 'application/json'; $req.Body = ($Body | ConvertTo-Json -Depth 8) }
    $resp = Invoke-RestMethod @req
    if ($resp.value) { return $resp.value } else { return $resp }
}

# --- Variables seguras de Automation ----------------------------------------
function Get-SocSecret {
    param([Parameter(Mandatory)][string] $Name)
    # En Azure Automation: Get-AutomationVariable; localmente cae a env var del mismo nombre.
    if (Get-Command Get-AutomationVariable -ErrorAction SilentlyContinue) {
        return Get-AutomationVariable -Name $Name
    }
    return [Environment]::GetEnvironmentVariable($Name)
}

function Invoke-SocHunting {
    # Advanced Hunting (Defender XDR) vía Graph /security/runHuntingQuery. Requiere ThreatHunting.Read.All.
    param([Parameter(Mandatory)][string] $Query)
    $token = Get-SocToken -ResourceUrl 'https://graph.microsoft.com'
    $body  = [System.Text.Encoding]::UTF8.GetBytes((@{ Query = $Query } | ConvertTo-Json))
    $resp  = Invoke-RestMethod -Method Post -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' `
                -Headers @{ Authorization = "Bearer $token" } -ContentType 'application/json; charset=utf-8' -Body $body
    return @($resp.results)
}

function Set-SocState {
    # Persiste estado (JSON) en Automation Variable para el delta semana-a-semana. La variable debe existir (la crea el deploy).
    param([Parameter(Mandatory)][string] $Name, [Parameter(Mandatory)][string] $Value)
    if (Get-Command Set-AutomationVariable -ErrorAction SilentlyContinue) {
        try { Set-AutomationVariable -Name $Name -Value $Value } catch { Write-Warning "[state] No se pudo guardar $Name : $($_.Exception.Message)" }
    }
}

Export-ModuleMember -Function Connect-SocContext, Get-SocContext, Get-SocToken,
    Invoke-SocKql, Invoke-SocGraph, Invoke-SocArm, Get-SocSecret, Set-SocState, Invoke-SocHunting

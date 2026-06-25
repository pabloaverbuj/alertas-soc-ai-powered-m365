# Invoke-ClaudeAnalysis.psm1
# Capa IA (M3). Analista SOC senior: toma los hallazgos REALES del reporte y produce
# resumen para dirección, observabilidad probabilística, triage de incidentes, correlación
# cross-módulo, priorización contextual y delta vs el reporte anterior.
# Provider configurable: 'azure-openai' (MI, sin keys) | 'anthropic' (x-api-key).

function Invoke-ClaudeAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $UserPrompt,
        [string] $SystemPrompt = (Get-SocAnalystSystemPrompt),
        [ValidateSet('critical','routine')][string] $Tier = 'critical',
        [object] $Settings = (Get-SocContext).Settings
    )
    $ai = $Settings.ai
    switch ($ai.provider) {
        'azure-openai' { return Invoke-SocAzureOpenAI -UserPrompt $UserPrompt -SystemPrompt $SystemPrompt -Ai $ai }
        default        { return Invoke-SocAnthropic   -UserPrompt $UserPrompt -SystemPrompt $SystemPrompt -Tier $Tier -Ai $ai }
    }
}

function Invoke-SocAzureOpenAI {
    param([string]$UserPrompt, [string]$SystemPrompt, [object]$Ai)
    $token = Get-SocToken -ResourceUrl 'https://cognitiveservices.azure.com'   # MI, sin API key
    $uri   = "$(($Ai.azureEndpoint).TrimEnd('/'))/openai/deployments/$($Ai.deployment)/chat/completions?api-version=$($Ai.azureApiVersion)"
    $body  = @{
        messages    = @(
            @{ role = 'system'; content = $SystemPrompt },
            @{ role = 'user';   content = $UserPrompt }
        )
        max_tokens  = $Ai.maxTokens
        temperature = 0.2
    } | ConvertTo-Json -Depth 8
    try {
        $resp = Invoke-RestMethod -Method Post -Uri $uri -Headers @{ Authorization = "Bearer $token" } `
                    -ContentType 'application/json; charset=utf-8' -Body ([System.Text.Encoding]::UTF8.GetBytes($body))
        return $resp.choices[0].message.content
    } catch {
        Write-Warning "[ai] Azure OpenAI falló: $($_.Exception.Message)"
        return $null
    }
}

function Invoke-SocAnthropic {
    param([string]$UserPrompt, [string]$SystemPrompt, [string]$Tier, [object]$Ai)
    $apiKey = Get-SocSecret -Name $Ai.apiKeyVariable
    if (-not $apiKey) { Write-Warning "[ai] Sin API key ($($Ai.apiKeyVariable)) - se omite narrativa IA."; return $null }
    $model = if ($Tier -eq 'critical') { $Ai.modelCritical } else { $Ai.modelRoutine }
    $body  = @{ model=$model; max_tokens=$Ai.maxTokens; system=$SystemPrompt; messages=@(@{ role='user'; content=$UserPrompt }) } | ConvertTo-Json -Depth 8
    try {
        $resp = Invoke-RestMethod -Method Post -Uri $Ai.endpoint -ContentType 'application/json; charset=utf-8' `
                    -Headers @{ 'x-api-key'=$apiKey; 'anthropic-version'=$Ai.apiVersion } -Body ([System.Text.Encoding]::UTF8.GetBytes($body))
        return ($resp.content | Where-Object type -eq 'text' | Select-Object -First 1).text
    } catch { Write-Warning "[ai] Anthropic falló: $($_.Exception.Message)"; return $null }
}

function Get-SocAnalystSystemPrompt {
    @"
Sos un analista SOC senior de Geonosis S.A. (tenant cloud-only Entra ID + M365, sin AD on-prem).
Recibís hallazgos REALES y estructurados de un reporte automatizado (incidentes, cobertura de
detección, identidad en riesgo, endpoints, rutas de ataque, crown jewels, threat intel, config
drift) y el estado del reporte anterior. Producís un análisis en español, accionable y honesto.

REGLAS DURAS:
- Usá SOLO los datos provistos. NO inventes IOCs, CVEs, usuarios ni números. Si falta evidencia, decilo explícito.
- Priorizá por impacto real al negocio y por proximidad a activos críticos (crown jewels / identidades privilegiadas).
- Las probabilidades son cualitativas (Alta/Media/Baja) justificadas por precondiciones presentes en el tenant, no inventadas.
- Markdown. Encabezados con '## '. Para tablas usá pipes. Sin relleno.
- NO cierres incidentes, NO cambies políticas, NO redactes comunicaciones externas, NO ejecutes ni ordenes remediaciones. Toda acción automática se PROPONE para aprobación humana.
- Sé explícito sobre tu confianza y sobre qué evidencia falta validar.

Generá EXACTAMENTE estas secciones, en este orden:

## Para dirección
Sin tecnicismos, 4 puntos en negrita: **Qué significa**, **Qué riesgo asumimos**, **Qué decisión hace falta**, **Qué pasa si no se corrige**.

## Riesgo principal de la semana
Un párrafo: el riesgo #1 y por qué.

## Impacto para el negocio
Qué activos/procesos se ven afectados y la consecuencia concreta (financiera, operativa, reputacional, cumplimiento).

## Top 3 prioridades
Lista numerada (1-3), una línea cada una.

## Qué cambió vs. el reporte anterior
Comparando con el estado previo provisto: qué mejoró, qué empeoró, qué es nuevo. Si no hay estado previo, decí "Primer reporte / sin línea base".

## Observabilidad probabilística
Tabla: | Escenario de ataque | Probabilidad | Precondiciones presentes | Indicadores a vigilar | Impacto |
Top 3-5 cadenas de ataque más probables, derivadas de los hallazgos reales.

## Triage de incidentes
Para cada incidente high/medium: **qué pasó**, técnica MITRE ATT&CK, hipótesis de ataque, evidencias faltantes, próximos pasos de investigación.

## Correlación entre módulos
Conectá señales de distintos dominios. Cubrí explícitamente (si los datos lo permiten):
- incidentes + usuarios en riesgo + device-code + CA en report-only + password spray (tendencia WoW)
- endpoints expuestos + vulnerabilidades KEV
- rutas de ataque + crown jewels
- gaps de SOC optimization + amenazas activas

## Priorización contextual
Reordená las acciones por contexto: qué va PRIMERO (afecta identidad privilegiada / crown jewel), qué puede ESPERAR, y qué REQUIERE VALIDACIÓN HUMANA antes de actuar.

## Confianza y evidencia
Tabla: | Conclusión / hallazgo | Confianza IA | Evidencia usada | Evidencia faltante | Próxima acción |
- Confianza IA = Alta / Media / Baja, según cuán sólida es la evidencia provista (no certeza absoluta).
- Evidencia usada = las señales concretas del input en que te basaste.
- Evidencia faltante = qué haría falta validar para confirmar.
- Próxima acción = Humano / Automático (propuesto, requiere aprobación) / Esperar.
Una fila por cada conclusión principal del análisis.
"@
}

Export-ModuleMember -Function Invoke-ClaudeAnalysis, Get-SocAnalystSystemPrompt

# Documentación — Geonosis SOC AI

> Estado: piloto en producción acotada. Reporte semanal automatizado de postura y amenazas.
> Última actualización: 2026-06-18.

---

## 1. Visión general

**Propósito.** `geonosis-soc-ai` automatiza la generación de un reporte semanal de seguridad (postura + amenazas + observabilidad probabilística) sobre el tenant de Geonosis (cloud-only Entra ID + M365, sin Active Directory on-premises), siguiendo el patrón de [Maester]: runbook en Azure Automation con Managed Identity, sin infraestructura local ni secrets en código.

**Estado actual.** Piloto / aislado. El reporte se entrega **solo a el administrador** (`admin@example.com`) por email + a un canal de Teams. Pensado para ampliarse a dirección.

**Alcance funcional.** El reporte cubre cinco dominios (A–E): Detección (incidentes + cobertura), Observabilidad (identidad, endpoints, comportamiento, rutas de ataque, sign-ins, password spray), Threat Intel (tendencias, cruce tendencia↔cobertura, device-code phishing), Higiene (datos/costos, config drift) y un Análisis IA ejecutivo (sección 1 del documento). Cierra con un plan de remediación priorizado.

**Problemas que resuelve.**
- Consolida en un solo documento señales que hoy están dispersas en Sentinel, Defender XDR, Entra ID Protection e Intune.
- Correlaciona entre dominios (lo que un analista hace mentalmente) vía IA.
- Da lectura ejecutiva para dirección + detalle técnico para remediación.
- Trackea evolución semana contra semana (delta).

**Qué NO cubre todavía.**
- No ejecuta remediaciones automáticas (solo analiza y recomienda).
- La IA no toma acciones, solo razona sobre datos provistos.
- Attack paths dependen de Defender for Cloud / Exposure Management (Geonosis sin IaaS → normalmente 0).
- UEBA requiere estar habilitado en Sentinel.
- ThreatFox/IOCs requiere API key (opcional).

---

## 2. Arquitectura general

| Componente | Rol |
|---|---|
| **Azure Automation** (`aa-geonosis-soc-ai`, RG `siem`, brazilsouth, runtime PowerShell 7.2) | Motor de ejecución del runbook. |
| **Managed Identity** (System-assigned, objectId `0b49aa02-1c76-43bd-8099-94eac147cf1b`) | Identidad de ejecución. Sin keys; autentica contra Log Analytics, Graph, ARM, Defender y Azure OpenAI. |
| **Microsoft Sentinel / Log Analytics** (`sentinel-workspace`, workspaceId `<workspace-id>`) | Fuente KQL (SigninLogs, Anomalies, Usage, SOC optimization recommendations). |
| **Microsoft Graph** | Incidentes de seguridad, identidad (ID Protection), Conditional Access, Intune (managedDevices + deviceManagementScripts), envío de email. |
| **Defender XDR / MDE** (`api.securitycenter.microsoft.com`) | Postura de endpoints (risk score, exposure). |
| **Azure Resource Graph / Defender for Cloud** | Attack paths (`microsoft.security/attackpaths`). |
| **Azure OpenAI** (`aoai-geonosis-soc`, eastus2, deployment `gpt-4o-mini`) | Capa IA (análisis ejecutivo). Auth por MI. |
| **Teams webhook + Email** | Canales de entrega. |

El runbook se construye **concatenando todos los módulos `.psm1` en un único archivo** PowerShell 7.2 (Azure Automation no monta la carpeta `src/modules`). La config (`settings.json`, `crown-jewels.json`, logo) viaja como Automation Variables.

---

## 3. Flujo de ejecución

Orquestador: `src/Invoke-GeonosisSocAi.ps1`. Parámetro `-Mode weekly|critical`.

**Orden A→E:**
1. **Base** — `Connect-SocContext` (auth MI, carga settings).
2. **B Detección** — incidentes + cobertura.
3. **C Observabilidad** — identidad, endpoints, comportamiento, attack paths, sign-ins, password spray.
4. **D Threat Intel** — tendencias, device-code, cruce tendencia↔cobertura.
5. **E Higiene** — datos/costos, config drift.
6. **A Informe** — ensambla `$data`, llama IA, renderiza HTML, publica a Teams + email, guarda estado.

**Modo weekly.** Reporte completo. Lookback = `schedule.lookbackDaysWeekly` (7 días). Schedule: lunes 10:00 ART (13:00 UTC).

**Modo critical.** Disparo out-of-band (schedule horario). Corre los colectores y **solo notifica si hay señal crítica**; si no, sale sin publicar (ni llama IA, ahorra costo). Condiciones de señal crítica:
- Incidente high abierto (`incidents.Critical`).
- Usuario high-risk (si `thresholds.highRiskUserAlert`).
- Nuevo attack path a crown jewel (si `thresholds.newAttackPathAlert`).
- Device-code sin bloqueo (si `thresholds.deviceCodeAlert` y hay sign-ins device-code).
- Config drift high.

**Delta semana-a-semana.** Al final de cada corrida se guarda un snapshot en la variable `GeonosisSocAi-LastState` (counts + incidentes). En la corrida siguiente se carga el snapshot previo y se pasa a la IA como `PrevState` para la sección "Qué cambió vs. el reporte anterior". La primera corrida reporta "sin línea base".

---

## 4. Configuración (`config/settings.json`)

```json
{
  "tenantId": "<tenant-id>",
  "workspace": { "name": "sentinel-workspace", "workspaceId": "<workspace-id>",
                 "subscriptionId": "<subscription-id>", "resourceGroup": "siem" },
  "ai": { "provider": "azure-openai",
          "azureEndpoint": "https://aoai-geonosis-soc.openai.azure.com",
          "deployment": "gpt-4o-mini", "azureApiVersion": "2024-10-21", "maxTokens": 3000,
          "endpoint": "...anthropic...", "apiKeyVariable": "GeonosisSocAi-AnthropicKey" },
  "delivery": { "teams": { "enabled": true, "webhookVariable": "GeonosisSocAi-TeamsWebhook" },
                "email": { "enabled": true, "from": "admin@example.com",
                           "to": ["admin@example.com"] } },
  "schedule": { "weeklyDay": "Monday", "timeLocal": "10:00",
                "timezone": "America/Argentina/Buenos_Aires", "lookbackDaysWeekly": 7 },
  "thresholds": { "criticalSeverities": ["high"], "highRiskUserAlert": true,
                  "deviceCodeAlert": true, "newAttackPathAlert": true },
  "coverageBaseline": { ... }
}
```

- **Azure OpenAI**: `provider=azure-openai`, endpoint del recurso, deployment `gpt-4o-mini`, api-version `2024-10-21`, `maxTokens=3000`. Los campos `endpoint`/`modelCritical`/`apiKeyVariable` quedan para el fallback Anthropic.
- **Entrega**: Teams habilitado (variable de webhook); email from/to.
- **Thresholds**: severidades críticas (`high`), y switches para alerta de high-risk users, device-code y attack paths nuevos.
- **coverageBaseline**: línea base histórica (referencia; la cobertura real se lee en vivo, ver módulo B).

`settings.json` se sube a la variable `GeonosisSocAi-Settings`; el runbook la lee de ahí cuando no hay filesystem.

---

## 5. Crown jewels (`config/crown-jewels.json`)

Activos críticos para priorizar attack paths (M10) y dar contexto a la IA en la correlación ("¿afecta identidad privilegiada?").

**Buckets:** `identities` (con sub-tipos `role`, `user`, `servicePrincipal`), `groups`, `devices`, `cloudResources`. Cada entrada tiene `value` (se matchea como substring contra el `displayName`/impacto del target) y `tier` (0 = máximo).

Contenido real poblado: roles Global Administrator / Privileged Role Administrator / Security Administrator; los 5 Global Admins reales; el SP `mail-security-connector`; la MI de Maester; el workspace `SENTINEL-WORKSPACE`; Purview `Geonosis`; las Automation Accounts.

**Uso:**
- `Get-AttackPaths` matchea targets de attack paths contra crown jewels.
- La IA recibe las identidades tier-0 para priorizar ("esto va primero porque afecta identidad privilegiada").

**Sensibilidad:** lista de los activos más valiosos del tenant. Tratar como información sensible (variable no-secreta pero confidencial; ver sección 18).

---

## 6. Variables de Azure Automation

| Variable | Encriptada | Contenido | Quién la actualiza |
|---|---|---|---|
| `GeonosisSocAi-Settings` | No | `settings.json` completo | Deploy (desde repo) |
| `GeonosisSocAi-CrownJewels` | No (sensible) | `crown-jewels.json` | Deploy |
| `GeonosisSocAi-TeamsWebhook` | Sí | URL del webhook (reusa el de Maester) | Deploy (copia de Maester) |
| `GeonosisSocAi-AbuseChKey` | Sí | API key ThreatFox (opcional; vacía hoy) | Manual |
| `GeonosisSocAi-LastState` | No | Snapshot JSON para el delta | El runbook (cada corrida) |
| `GeonosisSocAi-LogoB64` | No | Isologo PNG en base64 | Deploy (desde `config/geologo.b64.txt`) |
| `GeonosisSocAi-AnthropicKey` | Sí | Fallback Anthropic (TODO, sin usar) | — |

**Secretas:** TeamsWebhook, AbuseChKey, AnthropicKey. **No secretas pero confidenciales:** CrownJewels. **No secretas:** Settings, LastState, LogoB64.

**Lectura/modificación:** solo quien tenga rol sobre la Automation Account (Contributor/Automation Operator). El runbook (MI) lee vía `Get-AutomationVariable` y escribe `LastState` vía `Set-AutomationVariable`.

**Redeploy:** `Deploy-GeonosisSocAi.ps1` hace upsert de Settings/CrownJewels/LogoB64 desde el repo; las secretas con valor `TODO` se cargan manualmente (excepto el webhook, que se copia de Maester).

---

## 7. Módulo A — Reporte (`A-Report/New-SocReport.psm1`)

Genera el reporte como **documento formal** y lo entrega.

- **`New-SocReport`** — arma el objeto reporte: título, modo, período, ejecutivo (IA), `$Data`, y el plan de remediación (`Build-SocRemediation`).
- **`ConvertTo-SocHtml`** — render del documento: portada con **banda oscura + logo oficial** (`cid:geologo`), tabla de metadatos, **KPI cards**, **panel visual** (tortas QuickChart + barras CSS), índice numerado, secciones 1–6 con tablas y badges de severidad, y plan de remediación priorizado.
- **Branding** (sección 7 de este doc / toolkit): paleta de marca (azul `#0000FF` primario, negro `#2D2F31`, naranjas, amarillo), fuente Inter Tight. CSS inline en `Get-SocHtmlShell`.
- **Logo inline** — `Send-SocEmail` adjunta el PNG como `fileAttachment` `isInline=true contentId=geologo`; el HTML lo referencia con `cid:geologo` (Outlook no renderiza data-URI).
- **Panel visual** — `New-SocChartPair` (torta + barras), `New-SocBarChart`, `New-SocPie` (QuickChart), `New-SocWowBadge`.
- **Render Markdown de la IA** — `ConvertFrom-SocMarkdown` soporta encabezados `##/###`, **negritas**, listas ordenadas/no, y **tablas markdown** (para la tabla de observabilidad probabilística).
- **Plan de remediación** — `Build-SocRemediation` deriva acciones P1/P2/P3 de los hallazgos (incidentes críticos, drift, high-risk users, device-code, gaps, endpoints).
- **Comportamiento sin IA** — si la IA no responde, la sección 1 cae a un resumen ejecutivo determinista (bullets de los hallazgos).

---

## 8. Módulo B — Detección

**`B-Detection/Get-SocIncidents.psm1`**
- Fuente: Graph Security API `/security/incidents` con `$expand=alerts` (`$top=50`, paginado).
- Extrae: severidad, estado, técnicas MITRE (de las alerts), conteo de alertas, **entidades** (UPN de usuarios, DNS de dispositivos, IPs).
- `Critical` = incidentes de severidad en `criticalSeverities` y estado ≠ `resolved` → alimenta el disparo critical (M2).

**`B-Detection/Get-SocCoverage.psm1`**
- Fuente: Sentinel SOC optimization, ARM `Microsoft.SecurityInsights/recommendations` (api-version `2024-01-01-preview`).
- Filtra `recommendationTypeId = Precision_Coverage*` (cobertura por amenaza).
- **Interpretación**: `state=Active` ⇒ gap de cobertura abierto; `CompletedBySystem` ⇒ cubierto.
- Devuelve filas por escenario, gaps, y resumen (ej: "37 recomendaciones [22 Active / 15 Completed], 12 de 21 escenarios con gap").

---

## 9. Módulo C — Observabilidad y postura

**`Get-IdentityRisk.psm1`** — Risky users (ID Protection P2, riskLevel high/medium), risk detections (impossible/unlikely travel, anomalous token). `HighRiskUsers` alimenta M2.

**`Get-EndpointPosture.psm1`**
- Defender machines (`api.securitycenter.microsoft.com/api/machines`): risk score, exposure level (requiere `Machine.Read.All`).
- Intune compliance (`/deviceManagement/managedDevices` noncompliant): dispositivos sin cifrado/incumplientes.
- **Inventario de usuario real** (`Get-IntuneUserInventory`): el primary user de Intune es siempre la cuenta de enrolamiento (admin user). Se lee el script Intune `GEO-CapturarUsuarioActivo` (`query user`) vía `deviceManagementScripts/{id}/deviceRunStates`, se parsea el marker `GEO-INVENTORY | host | fecha | sesión` y se mapea `deviceName → usuario real`. Requiere `DeviceManagementConfiguration.Read.All`.

**`Get-BehaviorAnomalies.psm1`** — UEBA, tabla `Anomalies` (KQL). Degrada con gracia si UEBA está apagado (sin datos → nota en el reporte).

**`Get-AttackPaths.psm1`** — Attack paths vía **Azure Resource Graph** (`securityresources | where type=='microsoft.security/attackpaths'`, POST `Microsoft.ResourceGraph/resources` api-version 2021-03-01). Matchea contra crown jewels (`Test-CrownJewelTarget`). Geonosis sin IaaS/Defender for Cloud ⇒ normalmente 0, sin error.

**`Get-SignInTelemetry.psm1`** — Sign-ins exitosos (KQL): top apps, países activos, **locaciones nuevas** (usuario/país visto por primera vez en la ventana).

**`Get-PasswordSpray.psm1`**
- Separa sign-ins OK (`ResultType=="0"`) vs fallidos.
- Firma de spray: error **50126** (credencial inválida) repartido entre muchos usuarios.
- **IPs origen de spray**: 1 IP con `>= SprayUserThreshold` (5) usuarios distintos.
- **Detalle de fallidos**: usuario, código, motivo, país/ciudad, IP, dispositivo, intentos.
- **Comparación semana vs semana anterior** (ventana actual vs `between ago(14d)..ago(7d)`), con % de avance/retroceso (`Get-SprayPct`, `New-SocWowBadge` — azul ▼ mejor / naranja ▲ peor).

---

## 10. Módulo D — Threat Intel

**`Get-ThreatTrends.psm1`** — CISA KEV (feed JSON oficial, CVEs agregados recientes) + ThreatFox/abuse.ch (IOCs). ThreatFox requiere header `Auth-Key` desde nov-2024 → variable opcional `GeonosisSocAi-AbuseChKey`; sin key, omite el feed. Filtra familias PhaaS/AiTM/EvilProxy/Tycoon/Kali365.

**`Compare-TrendCoverage.psm1`** — Cruza tendencias del mundo real contra los gaps de cobertura del tenant (por regex de nombre de escenario). Mapeos: AiTM/device-code (→ AiTM, Okta, BEC, Credential Exploitation), ransomware (→ Human Operated Ransomware), ERP/SAP/BEC. `Exposed` = el escenario relacionado está en estado Active.

**`Get-DeviceCodePhishing.psm1`** — Detección dedicada de device-code phishing (Kali365): (1) sign-ins con `AuthenticationProtocol == "deviceCode"` (KQL); (2) `Test-DeviceCodeBlocked` verifica si hay una CA **enforced** que bloquee el flujo. `AtRisk = -not Blocked`.

---

## 11. Módulo E — Higiene

**`Get-DataHygiene.psm1`** — Tabla `Usage` (KQL), ingesta billable por tabla (GB/30d), top tablas por costo. Insumo de valor del dato.

**`Get-ConfigDrift.psm1`** — Caza desvíos de configuración: CA en `enabledForReportingButNotEnforced` (report-only) que bloquean/exigen MFA o device-code; token protection deshabilitado; exclusiones amplias (≥8 usuarios/grupos). `High` (CA report-only) alimenta M2.

---

## 12. Capa IA (`Invoke-ClaudeAnalysis.psm1`)

- **Provider actual:** Azure OpenAI. **Fallback:** Anthropic (`x-api-key`). Branch por `settings.ai.provider`.
- **Auth:** Managed Identity → token de `https://cognitiveservices.azure.com` (sin keys). Rol data-plane `Cognitive Services OpenAI User` sobre el recurso.
- **Endpoint:** `{azureEndpoint}/openai/deployments/{deployment}/chat/completions?api-version={azureApiVersion}`.
- **Deployment:** `gpt-4o-mini`. **Temperatura:** 0.2. **maxTokens:** 3000.
- **System prompt** (`Get-SocAnalystSystemPrompt`): analista SOC senior; reglas duras (solo datos provistos, no inventar IOCs/CVEs/usuarios, probabilidades cualitativas justificadas).
- **Estructura obligatoria del análisis** (8 secciones): Para dirección · Riesgo principal · Impacto negocio · Top 3 prioridades · Qué cambió vs anterior · Observabilidad probabilística (tabla) · Triage de incidentes · Correlación entre módulos · Priorización contextual.
- **Datos que recibe:** ver sección 13. **No debe inventar:** IOCs, CVEs, usuarios, números no provistos.
- **Si falla la llamada:** `try/catch` devuelve `null` → el reporte usa el resumen determinista (warning `[ai]`, no rompe).

**Costo:** ~centavos/mes (solo weekly + criticals; el modo critical no llama IA si no hay señal).

---

## 13. Prompt y payload IA (`New-SocExecPrompt`)

Arma un JSON **rico** (no solo resúmenes) para que la IA pueda hacer triage y correlación:
- Incidentes (Id, título, severidad, estado, MITRE, alertas, entidades).
- Cobertura + lista de gaps.
- Risky users + detecciones.
- Endpoints noncompliant (con usuario real).
- Device-code (sign-ins, bloqueado, en riesgo).
- Password spray (resumen, IPs de spray, WoW).
- Config drift.
- Attack paths a crown jewels.
- Crown jewels (identidades privilegiadas tier-0).
- Threat intel (KEV, cruce tendencia↔cobertura).
- Higiene.
- **Estado anterior** (`PrevState`) para el delta.

**Sensibilidad:** este payload incluye UPNs, IPs, nombres de dispositivos y los activos críticos. Se envía a Azure OpenAI (mismo tenant, región eastus2). Ver sección 18 y roadmap (minimización de datos).

---

## 14. Entrega por email

- **Remitente / destinatarios:** `admin@example.com` (config `delivery.email`).
- **API:** Microsoft Graph `/users/{from}/sendMail` (requiere app role **`Mail.Send`**).
- **Cuerpo:** HTML completo. **Logo inline** (`cid:geologo`). **`saveToSentItems = false`**.
- **Encoding:** el body se envía como bytes UTF-8 (`charset=utf-8`) y todo el texto pasa por `HtmlEncode` (entidades) → sin mojibake en ningún cliente.
- **Si no llega:** ver Troubleshooting (sección 20).

---

## 15. Entrega por Teams

- **Canal:** vía webhook de **Power Automate Workflows** (reusa el de Maester; mismo formato `type:message/attachments` con Adaptive Card).
- **Contenido:** Adaptive Card con título, resumen corto (incidentes críticos / high-risk / gaps / drift) y top 5 acciones de remediación (FactSet).
- **Variable:** `GeonosisSocAi-TeamsWebhook`.
- **Si el webhook no existe:** warning `[teams] Sin webhook configurado`, no rompe; el detalle completo igual va por email.

---

## 16. Deployment (`deploy/Deploy-GeonosisSocAi.ps1`)

1. **Automation Account** `aa-geonosis-soc-ai` con **System-assigned Managed Identity** (idempotente).
2. **Roles Azure** a la MI (scope RG `siem`): Microsoft Sentinel Reader, Log Analytics Reader.
3. **App roles Graph/Defender** — se asignan **aparte** con `deploy/Grant-GraphRoles.ps1` (sesión limpia, sin Az: `Microsoft.Graph` y `Az` no conviven en una misma sesión — "Assembly with same name is already loaded"). Ver sección 17.
4. **Variables** (upsert): Settings, CrownJewels, LogoB64, LastState, y secretas (webhook copiado de Maester; AnthropicKey/AbuseChKey en `TODO`).
5. **Runbook único** — concatena los `.psm1` (quita `Export-ModuleMember`) + el cuerpo del orquestador desde `# --- base`, e importa como **PowerShell 7.2** (`-Published -Force`).
6. **Schedules** + `Register-AzAutomationScheduledRunbook`: Weekly (lunes 13:00 UTC, `-Mode weekly`) y Critical (cada 1h, `-Mode critical`).

**Re-publicación tras cambios:** reconstruir el runbook combinado y re-importar (`Import-AzAutomationRunbook ... -Published -Force`). Las variables de config se re-suben con el deploy.

> Nota operativa: la capa IA (recurso Azure OpenAI + rol `Cognitive Services OpenAI User`) se provisionó fuera del deploy base; documentar como prerequisito si se recrea el entorno.

---

## 17. Permisos

**Roles Azure (MI, scope RG `siem`):**
- *Microsoft Sentinel Reader* — leer recomendaciones SOC optimization.
- *Log Analytics Reader* — ejecutar KQL (SigninLogs, Anomalies, Usage).
- *Cognitive Services OpenAI User* (scope recurso `aoai-geonosis-soc`) — llamar al deployment de IA.

**Graph app roles (asignados a la MI):**
| Rol | Justificación |
|---|---|
| SecurityIncident.Read.All | Incidentes (M5). |
| SecurityAlert.Read.All | Alertas dentro de incidentes. |
| ThreatHunting.Read.All | Hunting / soporte. |
| IdentityRiskyUser.Read.All | Risky users (M7). |
| IdentityRiskEvent.Read.All | Risk detections (M7). |
| Policy.Read.All | Conditional Access (config drift, device-code). |
| DeviceManagementManagedDevices.Read.All | Compliance Intune (M8). |
| DeviceManagementConfiguration.Read.All | Script de inventario + deviceRunStates (usuario real). |
| Mail.Send | Envío del reporte por email. |

**Defender app role:** Machine.Read.All — postura de endpoints (Defender API).

> `ExposureManagement.Read.All` se intentó pero **Graph no lo expone** como app-role asignable; los attack paths se leen por **Azure Resource Graph** (no requiere ese permiso). El grant lo omite con warning.

**Consentimiento:** la asignación directa de app roles a la MI (`New-MgServicePrincipalAppRoleAssignment`) **es** el consentimiento — no requiere "Grant admin consent" del portal. Propagación al token: minutos a ~1h.

---

## 18. Seguridad y gobierno

- **Datos sensibles procesados:** UPNs, IPs, nombres de dispositivos, incidentes, riesgo de identidad, activos críticos (crown jewels).
- **Datos enviados por email/Teams:** el reporte completo (incidentes con entidades, usuarios en riesgo, detalle de password spray). Destinatario único hoy.
- **Datos enviados a Azure OpenAI:** el payload rico (sección 13) — mismo tenant, región eastus2. Pendiente: minimización/redacción (roadmap).
- **Datos a servicio externo (QuickChart):** las tortas mandan números **agregados** (no PII) a `quickchart.io`. Las barras CSS no tienen dependencia externa.
- **Crown jewels:** lista de los activos más valiosos; acceso = quien administre la Automation Account.
- **Reporte marcado CONFIDENCIAL — USO INTERNO** en la portada y footer; `saveToSentItems=false`.
- **Retención:** el email queda en el buzón del destinatario; el output de los jobs queda en Azure Automation (revisar política de retención). Sin almacenamiento adicional del reporte.
- **Control de destinatarios:** `settings.json` → `delivery.email.to`. Cambiar requiere re-subir la variable Settings.
- **Riesgo de Mail.Send:** permite enviar como cualquier buzón (app role amplio). Mitigación posible: RBAC for Applications scoping al buzón emisor.
- **Riesgo del webhook de Teams:** quien tenga la URL puede postear en el canal. Variable encriptada.
- **Logs:** los warnings (`[ai]`, `[teams]`, etc.) pueden contener fragmentos de datos; revisar quién accede al output de jobs.

---

## 19. Operación diaria/semanal

- **Validar que corrió:** `Get-AzAutomationJob -ResourceGroupName siem -AutomationAccountName aa-geonosis-soc-ai -RunbookName Invoke-GeonosisSocAi | sort CreationTime -desc | select -first 1`.
- **Revisar jobs / streams:** `Get-AzAutomationJobOutput -Id <jobId> -Stream Any` + `Get-AzAutomationJobOutputRecord`.
- **Probar weekly:** `Start-AzAutomationRunbook -ResourceGroupName siem -AutomationAccountName aa-geonosis-soc-ai -Name Invoke-GeonosisSocAi -Parameters @{Mode='weekly'} -Wait`.
- **Probar critical:** igual con `@{Mode='critical'}` (solo notifica si hay señal).
- **IA activa vs no configurada:** si la sección 1 trae las 8 secciones → IA OK; si dice "Capa IA no disponible" + resumen determinista → revisar el recurso/rol Azure OpenAI.
- **Actualizar destinatarios:** editar `settings.json` `delivery.email.to[]` y re-subir la variable `GeonosisSocAi-Settings` (o re-correr deploy).
- **Actualizar logo:** reemplazar `config/geologo.b64.txt` (PNG→base64) y re-subir `GeonosisSocAi-LogoB64`.
- **Actualizar crown jewels:** editar `config/crown-jewels.json` y re-subir `GeonosisSocAi-CrownJewels`.
- **Reiniciar línea base semanal:** vaciar `GeonosisSocAi-LastState` ⇒ próxima corrida reporta "sin línea base".
- **Revisar estado anterior:** leer el valor de `GeonosisSocAi-LastState`.

---

## 20. Troubleshooting

| Síntoma | Causa probable / acción |
|---|---|
| **IA no responde / sale sin capa IA** | Warning `[ai]`; revisar recurso Azure OpenAI, deployment, y rol `Cognitive Services OpenAI User` en la MI. |
| **Azure OpenAI 401/403** | Rol no propagado (esperar ~1h) o falta el rol data-plane. |
| **Graph 403** | App role no asignado/propagado; re-correr `Grant-GraphRoles.ps1` y esperar propagación. |
| **Sentinel/KQL sin datos** | Tabla no ingerida o lookback sin eventos; verificar conectores. |
| **UEBA sin datos** | Entity Behavior Analytics apagado en Sentinel (Settings > Entity behavior). |
| **ThreatFox sin key** | `GeonosisSocAi-AbuseChKey` vacía → feed omitido (esperado). |
| **Teams no publica** | Webhook vacío/incorrecto o flujo de Workflows caído; verificar `GeonosisSocAi-TeamsWebhook`. |
| **Email no llega** | Falta `Mail.Send`, buzón emisor inexistente, o destinatario inválido. |
| **Logo no aparece** | Outlook con imágenes bloqueadas ("descargar imágenes") o `GeonosisSocAi-LogoB64` vacía; `alt="Geonosis"` de fallback. |
| **Password spray sin datos** | Sin SigninLogs en la ventana, o sin fallos 50126. |
| **Device-code "expuesto"** | La CA que bloquea device-code está en report-only (hallazgo real, no bug). |
| **LastState no se guarda** | La variable debe existir (la crea el deploy); `Set-AutomationVariable` no la crea. |
| **Fallo al importar runbook** | Validar parseo del combinado; `Export-ModuleMember` debe quedar stripeado; runtime PowerShell 7.2. |

> Antecedentes ya resueltos: token MI como SecureString (Az≥5) → normalizado; `$PSScriptRoot` vacío en Automation → lecturas con `[System.IO.File]::Exists` + fallback a variable; `$top=200` en incidents → 50; mojibake de encoding → bytes UTF-8 + entidades HTML.

---

## 21. Limitaciones actuales

- Depende de que los datos estén presentes en Sentinel/Graph.
- UEBA requiere estar habilitado.
- ThreatFox requiere API key para traer IOCs.
- Attack paths dependen de Defender for Cloud / Exposure Management (Geonosis sin IaaS → 0).
- No ejecuta remediaciones automáticas; la IA solo analiza.
- El modo critical depende de los thresholds configurados.
- Destinatario único; sin segmentación por severidad todavía.

---

## 22. Roadmap

- Redacción / minimización de datos antes de enviarlos a la IA.
- Tests unitarios de módulos + dry-run local (mocks).
- Manejo independiente de errores Teams vs email.
- Retries / backoff para llamadas a APIs.
- Documentación formal de cambios (changelog/versionado).
- Export histórico de KPIs (tendencias multi-semana).
- Dashboard web o Power BI.
- Multi-destinatarios por severidad.
- Modo *executive-only* y modo *technical appendix*.

---

*Documento generado para el proyecto geonosis-soc-ai. Código fuente en `C:\Users\el administrador Sosto\.local\bin\geonosis-soc-ai`.*


# Agentes SOC asistidos por IA

Capa **interactiva** del proyecto: 10 subagentes Claude Code que triagean, investigan, cazan,
puntúan, preparan remediación (DryRun) y documentan incidentes nativos de Microsoft 365,
cableados a los MCP `m365-security` e `intune`.

Complementa —no reemplaza— al runbook desatendido (`src/`, Azure Automation, patrón Maester):
- **Runbook** = detección/observabilidad/reporte **programado** (semanal + disparo crítico).
- **Agentes** = investigación y respuesta **asistida por humano** cuando salta una alerta.

## Componentes

```
.claude/agents/soc-*.md         # 10 subagentes (project-scoped, los descubre Claude Code)
agents-soc/
  SHARED-GUARDRAILS.md          # reglas obligatorias: tenant, cuentas protegidas, modos, higiene
  contracts/                    # agent-io.schema.json + consolidated-output.schema.json
  scoring/risk-model.json       # modelo determinista de severidad (soc-riskscorer)
  playbooks/                    # 5 playbooks operativos (disparadores, flujo, KQL, remediación)
  ingest/                       # PUENTE con el runbook: Import-SocAlerts.ps1 + README
  inbox/                        # alertas normalizadas del runbook pendientes (runtime, no commitear)
  cases/<CaseId>/               # estado y artefactos por caso (runtime, no commitear)
  posture/                      # recomendaciones estructurales (soc-posture-advisor)
```

## Conexión con el runbook (Azure Automation)

Las alertas que detecta el runbook desatendido (incidentes high/critical, usuarios high-risk,
device-code, config drift, attack paths, password spray, hunting OAuth/phishing) **alimentan
directamente** a estos agentes:

```
Runbook → Export-SocAlerts (normaliza) → Automation Variable GeonosisSocAi-SocAlerts
       → Import-SocAlerts.ps1 (pull local) → agents-soc/inbox/ → soc-casemanager → cases/
```

Uso: `agents-soc/ingest/Import-SocAlerts.ps1` (trae el inbox) y luego "procesá el inbox SOC" en
Claude Code. Detalle en [`ingest/README.md`](ingest/README.md).

## Los 10 agentes (cadena de handoff)

| # | Agente | Rol | MCP / modo | Modelo |
|---|--------|-----|-----------|--------|
| 1 | `soc-casemanager` | abre CaseId, normaliza, enruta playbook | solo archivos | sonnet |
| 2 | `soc-triage-l1` | falso positivo vs incidente real | m365-security RO | sonnet |
| 3 | `soc-forense-l2` | persistencia: reglas, MFA, OAuth, sesiones | m365-security RO | opus |
| 4 | `soc-hunter-kql` | KQL de expansión (Sentinel/Defender) | genera KQL | sonnet |
| 5 | `soc-intune-context` | postura de dispositivo | intune RO | sonnet |
| 6 | `soc-riskscorer` | severidad final + confianza | scoring local | sonnet |
| 7 | `soc-remediator` | plan DryRun (PowerShell/Graph) | genera DryRun | opus |
| 8 | `soc-approver` | HumanApprovalGate | registra decisión | opus |
| 9 | `soc-reporter` | reporte ejecutivo + técnico | archivos | sonnet |
| 10 | `soc-posture-advisor` | mejoras estructurales del tenant | m365+intune RO | opus |

## Flujo

```
soc-casemanager
  -> soc-triage-l1
  -> soc-forense-l2        (si hay/sospecha persistencia)
  -> soc-hunter-kql        (si campaña / múltiples entidades)
  -> soc-intune-context    (si usuario con dispositivo)
  -> soc-riskscorer
  -> soc-remediator        (si severidad HIGH/CRITICAL)
  -> soc-approver          (toda acción sensible)
  -> soc-reporter
  -> soc-posture-advisor   (hallazgos recurrentes)
```

Reglas de handoff: falso positivo en triage → directo a reporter. Severidad HIGH/CRITICAL → remediator.
Acción sensible → approver. Todo caso cerrado → reporter.

## Cómo se usa

Desde Claude Code en este proyecto, invocás los agentes por `subagent_type` (ej. `soc-casemanager`)
vía el Tool Agent, o pedís en lenguaje natural "abrí un caso SOC por esta alerta" y la cadena arranca.

Ejemplo:
> "Llegó alerta de Entra ID Protection: user@example.com en high risk con sign-in deviceCode desde IP rara.
> Corré el flujo SOC."

`soc-casemanager` abre `SOC-YYYYMMDD-NNNN`, elige `M365_DEVICE_CODE_PHISHING`, y deriva.
**Nota**: si el usuario pertenece a `config/crown-jewels.json` como cuenta protegida, cualquier contención queda `pending_approval`.

## Garantías (criterios de aceptación)

- Cada alerta genera un `CaseId`.
- Toda remediación nace en `DryRun`; las acciones sensibles quedan `pending_approval`.
- El reporte separa evidencia confirmada / hipótesis / evidencia faltante.
- No se almacenan ni imprimen secretos/tokens. Permisos Graph mínimos por acción.
- Cada acción ejecutada registra CaseId, aprobador (humano), timestamp y resultado.

## Madurez

- **Fase 1 (actual)**: asistido — KQL y DryRun por IA, aprobación humana, reporte enriquecido.
- **Fase 2**: enriquecimiento/scoring automático, historial de falsos positivos.
- **Fase 3**: contención automática solo para crítico con evidencia fuerte; la automatización
  estable vive en el runbook (Azure Automation / Functions / Logic Apps), **no** en la IA interactiva.

# Arquitectura — Alertas SOC AI Powered M365

> Documento de arquitectura, flujos y diseño del proyecto. Para el uso práctico ver el [README](../README.md); para el detalle técnico de despliegue, la [Documentación técnica](DOCUMENTACION.md).

---

## 💡 Idea

Un **SOC "as code"** para equipos de IT chicos y entornos **cloud-only de Microsoft 365**.

En vez de pagar un SIEM/SOAR de terceros o un SOC gestionado, la idea es **orquestar la seguridad usando solo lo que ya viene en el stack de Microsoft** — Sentinel, Defender XDR, Entra ID, Intune y Graph — sumando Azure Automation para correrlo desatendido y una capa de IA para redactar y correlacionar. Todo se entrega al canal donde el equipo ya vive: **Microsoft Teams**. Costo operativo: del orden de **centavos por mes**.

## 🎯 Misión

Que un equipo de IT reducido pueda **operar como un SOC**: ver su postura, detectar lo que realmente importa, triagear con contexto y responder con trazabilidad — **sin herramientas extra, sin un analista 24/7, y sin que la IA tome decisiones destructivas por su cuenta.**

## ✅ Objetivos

| Objetivo | Cómo lo logra |
|----------|---------------|
| **Centralizar** señales dispersas | Normaliza incidentes, riesgos, drift y hunting desde Sentinel, Defender, Entra e Intune en un formato único |
| **Reportar** postura y amenazas | Informe semanal estructurado (KPIs, incidentes, cobertura, tendencias, remediación priorizada) a email + Teams |
| **Alertar** sin ruido | Firma de estado + deduplicación: notifica solo cuando algo **cambia**, no cada corrida |
| **Enriquecer** para decidir | Motor de riesgo por entidad, correlación cross-módulo, evidencia y entidades por incidente |
| **Responder** con seguridad | Agentes que investigan y preparan remediación en **DryRun**; acciones sensibles con aprobación humana |
| **Minimizar costo** | Solo stack Microsoft + IA *metered*; sin licencias de SIEM/SOAR de terceros |
| **Trazar todo** | Cada alerta → `CaseId`; cada acción registra aprobador humano, timestamp y resultado |

## 🧭 Principios de diseño

- **Humano en el loop** — la IA resume, prioriza y propone; **no ejecuta** cambios por su cuenta.
- **Determinismo donde importa** — reglas, KQL y scoring son deterministas; la IA entra solo en narrativa y correlación.
- **Read-first, DryRun antes de actuar** — nada destructivo sin un paso previo de solo-lectura y una aprobación.
- **Mínimo privilegio** — scopes de Graph por acción, los MCP de los agentes son de **solo lectura**.
- **Sin secretos en el repo** — credenciales en variables cifradas de Azure Automation; el estado con PII nunca se versiona.

---

## 🏛️ Arquitectura: dos capas

El sistema combina una capa **desatendida** (detección/reporte programado) con una capa **interactiva** (respuesta asistida por humano). Se comunican por un puente de datos.

```mermaid
flowchart TB
    subgraph SRC["☁️ Fuentes Microsoft 365"]
        direction LR
        G["Microsoft Graph"]
        D["Defender XDR"]
        S["Sentinel / Log Analytics"]
        I["Intune"]
    end

    subgraph L1["⚙️ Capa 1 — Runbook desatendido · Azure Automation + Managed Identity"]
        direction TB
        ENG["Motor PowerShell + KQL<br/>(módulos A–G)"]
        RISK["Risk Engine<br/>+ Estado semanal"]
        OUT["📄 Reporte HTML / Email<br/>💬 Teams Alert"]
        ENG --> RISK --> OUT
    end

    subgraph BR["🔗 Puente de alertas"]
        direction TB
        EXP["Export-SocAlerts<br/>→ Automation Variable"]
        IMP["Import-SocAlerts<br/>→ inbox/"]
        EXP --> IMP
    end

    subgraph L2["🤖 Capa 2 — Agentes SOC · Claude Code + MCP (solo lectura)"]
        direction TB
        CASE["soc-casemanager<br/>(abre CaseId)"]
        CHAIN["Cadena de 10 agentes<br/>triage → forense → hunt → score"]
        GATE["🔒 Human Approval Gate"]
        CASE --> CHAIN --> GATE
    end

    SRC --> ENG
    RISK --> EXP
    IMP --> CASE

    classDef src fill:#0078D4,color:#fff,stroke:#034a77,stroke-width:1px
    classDef runbook fill:#2560E0,color:#fff,stroke:#143a8c,stroke-width:1px
    classDef bridge fill:#6B21A8,color:#fff,stroke:#3b1263,stroke-width:1px
    classDef agents fill:#107C10,color:#fff,stroke:#0a4d0a,stroke-width:1px
    class G,D,S,I src
    class ENG,RISK,OUT runbook
    class EXP,IMP bridge
    class CASE,CHAIN,GATE agents
```

| | Capa 1 — Runbook | Capa 2 — Agentes |
|---|---|---|
| **Qué es** | Automatización **programada** | Investigación/respuesta **asistida por humano** |
| **Dónde corre** | Azure Automation (Managed Identity, sin keys) | Claude Code + MCP `m365-security` / `intune` |
| **Cuándo** | Semanal (lunes) + disparo crítico (horario) | Cuando salta una alerta y un humano la trabaja |
| **Rol** | Detectar, observar, reportar, deduplicar | Triagear, cazar, puntuar, preparar remediación |

---

## ⚙️ Capa 1 — Runbook desatendido

Corre en Azure Automation con **System-Assigned Managed Identity** (autentica contra Graph, Log Analytics, ARM, Defender y Azure OpenAI sin almacenar secretos). Sigue el patrón *Maester*: sin infra local, entrega a Teams + email.

**Responsabilidades:** consultar las fuentes → calcular tendencias y deltas semanales → detectar eventos críticos → generar el reporte → persistir estado para comparación y deduplicación.

**Módulos (`src/modules/`):**

| Área | Módulo | Propósito |
|---|---|---|
| A | `A-Report` | Reporte semanal, alertas críticas, narrativa IA |
| B | `B-Detection` | Incidentes, cobertura SOC, gaps de detección |
| C | `C-Observability` | Identidad, endpoints, sign-ins, password spray, attack paths |
| D | `D-ThreatIntel` | Tendencias, device-code phishing, cruce amenaza/cobertura |
| E | `E-Hygiene` | Drift de configuración, higiene de datos, posture score |
| F | `F-Engine` | Motor de riesgo y exportación de alertas normalizadas |
| G | `G-Hunting` | Hunting de phishing, OAuth, privilegios y clicks sospechosos |

**Cadencia:** reporte **completo los lunes**; el resto de los días, **disparo crítico** solo si la *firma de señales* cambió (evita renotificar lo mismo).

---

## 🤖 Capa 2 — Agentes SOC: propósito y orquestación

La capa interactiva son **10 subagentes Claude Code** (project-scoped en `.claude/agents/soc-*.md`) cableados a los MCP `m365-security` e `intune` en **modo solo lectura**. Investigan, cazan, puntúan, preparan remediación (DryRun) y documentan — **complementan, no reemplazan** al runbook.

### Propósito de cada agente

| # | Agente | Propósito | MCP / modo | Modelo |
|---|--------|-----------|-----------|--------|
| 1 | `soc-casemanager` | Abre el `CaseId`, normaliza la alerta y **enruta** al playbook correcto | solo archivos | sonnet |
| 2 | `soc-triage-l1` | Primera decisión: **¿falso positivo o incidente real?** con contexto mínimo | m365-security RO | sonnet |
| 3 | `soc-forense-l2` | Caza **persistencia**: reglas de buzón, MFA, consents OAuth, sesiones activas | m365-security RO | **opus** |
| 4 | `soc-hunter-kql` | Genera **KQL de expansión** (Sentinel/Defender) para buscar campaña / más víctimas | genera KQL | sonnet |
| 5 | `soc-intune-context` | Aporta **postura del endpoint** (compliance, cifrado, estado del device) | intune RO | sonnet |
| 6 | `soc-riskscorer` | Calcula **severidad final + confianza** con el modelo determinista de scoring | scoring local | sonnet |
| 7 | `soc-remediator` | Prepara el **plan de remediación en DryRun** (PowerShell/Graph), nunca lo ejecuta | genera DryRun | **opus** |
| 8 | `soc-approver` | **Human Approval Gate**: registra la decisión humana sobre acciones sensibles | registra decisión | **opus** |
| 9 | `soc-reporter` | Redacta el **reporte ejecutivo + técnico** separando evidencia/hipótesis/faltante | archivos | sonnet |
| 10 | `soc-posture-advisor` | Convierte **incidentes recurrentes en mejoras estructurales** del tenant | m365+intune RO | **opus** |

> Los agentes de mayor criticidad (forense, remediación, aprobación, postura) corren en **opus**; la cadena de triage/hunting/scoring/reporte en **sonnet**.

### Cadena de handoff

```mermaid
flowchart TB
    A1(["1 · casemanager"]) --> A2{"2 · triage-l1"}
    A2 -->|"falso positivo"| A9
    A2 -->|"incidente real"| A3["3 · forense-l2"]
    A3 --> A4["4 · hunter-kql"]
    A4 --> A5["5 · intune-context"]
    A5 --> A6{"6 · riskscorer"}
    A6 -->|"LOW / MEDIUM"| A9
    A6 -->|"HIGH / CRITICAL"| A7["7 · remediator"]
    A7 --> A8["🔒 8 · approver"]
    A8 --> A9["9 · reporter"]
    A9 --> A10["10 · posture-advisor"]

    classDef sonnet fill:#2560E0,color:#fff,stroke:#143a8c
    classDef opus fill:#6B21A8,color:#fff,stroke:#3b1263
    classDef gate fill:#C2410C,color:#fff,stroke:#7c2a08
    classDef done fill:#107C10,color:#fff,stroke:#0a4d0a
    class A1,A2,A4,A5,A6 sonnet
    class A3,A7,A10 opus
    class A8 gate
    class A9 done
```

**Reglas de handoff:** falso positivo en triage → directo a `reporter`. Severidad **HIGH/CRITICAL** → `remediator`. Toda **acción sensible** → `approver`. Todo caso cerrado → `reporter`. Hallazgos recurrentes → `posture-advisor`.

---

## 🔗 El puente runbook ↔ agentes

Las alertas que detecta el runbook alimentan directamente a los agentes mediante una Automation Variable, sin acoplar ambas capas:

```mermaid
sequenceDiagram
    autonumber
    participant RB as Runbook (Azure Automation)
    participant AV as Automation Variable<br/>GeonosisSocAi-SocAlerts
    participant IM as Import-SocAlerts.ps1
    participant IN as agents-soc/inbox/
    participant CM as soc-casemanager

    RB->>RB: detecta señales (INC/HRU/DEVICECODE/DRIFT/SPRAY/OAUTH/PHISH)
    RB->>AV: Export-SocAlerts (normaliza + dedup por alertId)
    IM->>AV: pull (Get-AzAutomationVariable)
    IM->>IN: escribe N .json (dedup vs casos/inbox)
    CM->>IN: consume el inbox
    CM->>CM: crea CaseId → enruta playbook → cadena de agentes
```

Formato de alerta: cada señal se normaliza con un `alertId` estable (clave de dedup) y se mapea a `category` + `recommendedPlaybook`. Hay **5 playbooks** operativos: BEC, password spray, device-code phishing, OAuth consent y mailbox forwarding.

---

## 🔒 Modelo de seguridad y guardrails

- `config/settings.json` y `config/crown-jewels.json` son **locales** y no se versionan.
- `agents-soc/cases/` e `inbox/` contienen evidencia *runtime* con PII → **fuera de Git**.
- Las credenciales viven como **variables cifradas** de Azure Automation.
- Las **cuentas protegidas** (break-glass, roles privilegiados, SP sensibles de `crown-jewels.json`) **nunca** reciben contención automática → siempre `pending_approval`.
- Toda remediación nace en **DryRun**; las acciones sensibles quedan `pending_approval`.
- No se almacenan ni imprimen secretos/tokens. Permisos de Graph **mínimos por acción**.
- El reporte separa siempre **evidencia confirmada / hipótesis / evidencia faltante**.

---

## 📈 Madurez (hoja de ruta)

```mermaid
flowchart LR
    F1["Fase 1 — Asistido<br/><small>(actual)</small>"] --> F2["Fase 2 — Semi-automático"] --> F3["Fase 3 — Contención selectiva"]

    classDef cur fill:#107C10,color:#fff,stroke:#0a4d0a
    classDef next fill:#394149,color:#fff,stroke:#20262e
    class F1 cur
    class F2,F3 next
```

- **Fase 1 (actual):** KQL y DryRun generados por IA, **aprobación humana**, reporte enriquecido.
- **Fase 2:** enriquecimiento/scoring automático + historial de falsos positivos.
- **Fase 3:** contención automática **solo para crítico con evidencia fuerte**; la automatización estable vive en el runbook (Azure Automation / Functions / Logic Apps), **no** en la IA interactiva.

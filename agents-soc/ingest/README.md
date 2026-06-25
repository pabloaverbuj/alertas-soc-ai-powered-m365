# Puente runbook → agentes SOC interactivos

Conecta las **alertas que produce el runbook Azure Automation** (`Invoke-GeonosisSocAi`) con los
**agentes interactivos** (`soc-*`). No hay filesystem compartido: el medio es una **Automation
Variable**, igual que el resto del estado del runbook.

```
Runbook (Azure Automation, MI)                     Local (Claude Code)
─────────────────────────────                      ───────────────────
señales críticas (INC/HRU/AP/                        Import-SocAlerts.ps1
  DRIFT/DEVICECODE/SPRAY/OAUTH/PHISH)                  (Get-AzAutomationVariable)
        │ Export-SocAlerts (normaliza)                       │
        ▼                                                    ▼
  Automation Variable  ────────  pull  ───────────►   agents-soc/inbox/*.json
  GeonosisSocAi-SocAlerts                                    │
                                                             ▼  soc-casemanager
                                                      agents-soc/cases/<CaseId>/
                                                             │  (triage→forense→…→reporter)
```

## Lado runbook (ya integrado en `src/`)

- `src/modules/F-Engine/Export-SocAlerts.psm1` normaliza las señales accionables al schema del
  **SOC Alert Normalizer** (`alertId` estable, `source`, `category`, `severity`, `entities`,
  `recommendedPlaybook`, `status:new`).
- El orquestador (`Invoke-GeonosisSocAi.ps1`) lo llama en **cada corrida** (weekly y critical),
  **antes** del dedup de notificación, y persiste el array en la variable `GeonosisSocAi-SocAlerts`.
- El deploy crea la variable (`deploy/Deploy-GeonosisSocAi.ps1`).

Señales mapeadas → categoría → playbook:

| Señal runbook | category | playbook |
|---|---|---|
| `INC:` incidente high/critical | phishing_bec / oauth / spray / device_code / mailbox (por título) | el que corresponda |
| `HRU:` usuario high-risk | risky_user | M365_ACCOUNT_COMPROMISE_BEC |
| `DEVICECODE:atRisk` | device_code_phishing | M365_DEVICE_CODE_PHISHING |
| `SPRAY:` IP concentrada | password_spray | M365_PASSWORD_SPRAY |
| `OAUTH:` app consent (hunting) | oauth_app_consent | M365_OAUTH_CONSENT |
| `PHISH:` click-through (hunting) | phishing_bec | M365_ACCOUNT_COMPROMISE_BEC |
| `AP:` attack path a crown jewel | attack_path | UNMAPPED → soc-posture-advisor |
| `DRIFT:` config drift high (CA report-only) | config_drift | UNMAPPED → soc-posture-advisor |

## Lado local

```powershell
# 1. Traer las alertas del runbook al inbox (login Azure interactivo si hace falta)
cd "C:\Users\Pablo Sosto\.local\bin\geonosis-soc-ai\agents-soc\ingest"
./Import-SocAlerts.ps1            # o -WhatIf para previsualizar

# 2. En Claude Code, dentro del proyecto:
#    "procesá el inbox SOC"   (arranca soc-casemanager → abre casos → enruta la cadena)
```

`Import-SocAlerts.ps1` deduplica por `alertId` contra los casos ya abiertos y el inbox, así que
es idempotente: corrers múltiples no duplican casos. Una alerta ya cerrada no se reabre salvo que
el runbook emita un `alertId` nuevo (señal nueva).

## Automatizar el pull (opcional)

El pull es local y necesita identidad de Pablo (lectura de la Automation Variable). Para que sea
desatendido, las opciones (mismo patrón que el sync de devices):
- **Scheduled Task** en un host con `Az.Automation` + identidad con `Automation Variable read` sobre `aa-geonosis-soc-ai`.
- O exponer las alertas a un canal que el host ya consuma (Teams/cola) en vez de la variable.

Por ahora, Fase 1 = **pull manual + procesamiento asistido** (humano en el loop), que es justo lo
que pide el diseño hasta tener historial de falsos positivos.

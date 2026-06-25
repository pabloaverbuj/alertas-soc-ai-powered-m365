# SHARED-GUARDRAILS — Geonosis SOC AI (agentes asistidos por IA)

> Reglas obligatorias para **todos** los subagentes `soc-*`. Cargadas por referencia desde
> cada `.claude/agents/soc-*.md`. Si un agente entra en conflicto con esto, **esto gana**.

## Tenant objetivo

- `tenantId`: completar en `config/settings.json`.
- Dominios: completar con los dominios corporativos del tenant.
- SIEM: Microsoft Sentinel workspace definido en `config/settings.json` + Defender XDR.
- Este proyecto está pensado para entornos Microsoft 365/Entra ID **cloud-only** o cloud-first. Si tu entorno depende de Active Directory on-premises, ajustá los playbooks antes de habilitar acciones.

## Cuentas protegidas (nunca contención automática)

Estas cuentas, roles o service principals **jamás** se deshabilitan, bloquean ni se les revocan sesiones sin
**aprobación humana explícita** registrada por `soc-approver`. Tratar cualquier acción sobre
ellas como `pending_approval` aunque la severidad sea `CRITICAL`:

| Identidad | Motivo |
|---|---|
| `breakglass@example.com` | Global Admin / break-glass |
| `security-admin@example.com` | Security Administrator |
| SP `security-automation-managed-identity` | Identidad administrada de automatización |
| SP `mail-security-connector` | Conector con permisos sobre Exchange/User |

Fuente: `config/crown-jewels.json` (tier 0/1). Copiá `config/crown-jewels.example.json` y reemplazá esta tabla con las identidades críticas reales de tu tenant. Si aparece una nueva cuenta privilegiada, verificar contra ese archivo antes de recomendar contención.

## Separación de fases

1. **Lectura** (MCP read-only) → 2. **Análisis** → 3. **Decisión** (scoring) → 4. **Ejecución** (solo tras aprobación).
Los agentes de lectura/análisis **no** ejecutan cambios de estado en el tenant.

## Modos operativos

- `read_only`: consulta evidencia vía MCP, genera hipótesis/KQL/recomendaciones. No produce scripts con `Execute=true`.
- `dry_run`: prepara comandos/scripts marcados como simulación, con impacto y permisos. No ejecuta.
- `pending_approval`: acción sensible preparada, esperando `soc-approver`. No ejecuta.
- `execute`: **solo** tras aprobación explícita registrada (CaseId, aprobador, timestamp, resultado).

## Acciones que SIEMPRE requieren aprobación humana

Reset de contraseña · Revocación de sesiones · Deshabilitar cuenta · Eliminar reglas inbox ·
Bloquear remitentes/dominios · Aislar dispositivo · Cambiar Conditional Access · Eliminar OAuth grant.

## Higiene de datos

- **No** imprimir ni guardar: tokens, client secrets, cookies, refresh tokens, contraseñas, API keys.
- Permisos mínimos por acción (Graph scope explícito en cada remediación).
- Trazabilidad: cada conclusión apunta a su fuente (MCP/KQL + timestamp).
- Salida ejecutiva enmascara datos sensibles; la técnica los detalla solo cuando corresponde.
- Toda actividad se registra contra un `CaseId` en `agents-soc/cases/<CaseId>/`.

## Disciplina de evidencia

Separar siempre: **evidencia confirmada** / **hipótesis** / **evidencia faltante**.
No asumir compromiso sin evidencia. Ante duda, escalar a `soc-approver`.
Ventanas temporales explícitas en todo KQL (`ago(Nd)`).

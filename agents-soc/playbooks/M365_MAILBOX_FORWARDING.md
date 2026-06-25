# Playbook: M365_MAILBOX_FORWARDING

Mailbox forwarding / reglas inbox maliciosas.

## Disparadores
- Regla inbox nueva · forward externo.
- Regla que mueve a Deleted Items, RSS, Archive o carpeta oculta.
- Regla que marca como leído (oculta evidencia).

## Flujo de agentes
`soc-casemanager → soc-forense-l2 → soc-hunter-kql → soc-riskscorer → soc-remediator → soc-approver → soc-reporter`

## Evidencia requerida
Buzón afectado · regla(s) (nombre, condición, acción, destino) · forward externo (dominio destino) ·
quién/cuándo la creó · sign-ins previos del usuario.

## KQL

```kql
CloudAppEvents
| where TimeGenerated > ago(14d)
| where ActionType has_any ("New-InboxRule", "Set-InboxRule", "Set-Mailbox", "Set-MailboxAutoReplyConfiguration")
| project TimeGenerated, AccountDisplayName, ActionType, RawEventData
| order by TimeGenerated desc
```

## Remediación (DryRun → aprobación)
**Exportar las reglas existentes como evidencia ANTES de tocar nada** · eliminar regla maliciosa
con aprobación · revocar sesiones · resetear contraseña si hay evidencia de compromiso ·
revisar envío saliente del buzón.

# Playbook: M365_ACCOUNT_COMPROMISE_BEC

Compromiso de cuenta por phishing / BEC.

## Disparadores
- Login sospechoso posterior a correo de phishing.
- Regla inbox anómala · forwarding externo.
- Usuario con riesgo alto/medio · cambio de métodos MFA.
- OAuth consent sospechoso · envío BEC inusual.

## Flujo de agentes
`soc-casemanager → soc-triage-l1 → soc-forense-l2 → soc-hunter-kql → soc-intune-context → soc-riskscorer → soc-remediator → soc-approver → soc-reporter`

## Evidencia requerida
Usuario afectado · sign-ins recientes (IP/país/app) · MFA requerido/satisfecho/fallido ·
risk detections · EmailEvents relacionados · reglas inbox · forwarding · AuditLogs de cambios
de seguridad · dispositivos asociados.

## KQL

```kql
let TargetUser = "usuario@geonosis.com.ar";
SigninLogs
| where UserPrincipalName =~ TargetUser
| where TimeGenerated > ago(7d)
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, Location, ConditionalAccessStatus, ResultType, ResultDescription
| order by TimeGenerated desc
```

```kql
let TargetSubject = "ASUNTO SOSPECHOSO";
EmailEvents
| where TimeGenerated > ago(14d)
| where Subject has TargetSubject
| project TimeGenerated, RecipientEmailAddress, SenderFromAddress, Subject, DeliveryAction, ThreatTypes, NetworkMessageId
```

```kql
CloudAppEvents
| where TimeGenerated > ago(14d)
| where ActionType has_any ("New-InboxRule", "Set-InboxRule", "Set-Mailbox", "Consent to application")
| project TimeGenerated, AccountDisplayName, ActionType, Application, RawEventData
| order by TimeGenerated desc
```

## Remediación (DryRun → aprobación)
Revocar sesiones · resetear contraseña · remover reglas inbox maliciosas · revisar métodos MFA ·
revisar OAuth consent · deshabilitar cuenta solo si compromiso activo + CRITICAL · aislar dispositivo
si hay evidencia endpoint. Todas pasan por `soc-approver`. Si el afectado es cuenta protegida →
`pending_approval` siempre.

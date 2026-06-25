# Playbook: M365_PASSWORD_SPRAY

## Disparadores
- Aumento de sign-ins fallidos · error `50126` contra múltiples usuarios.
- IP origen repetida · usuarios atacados por la misma IP/ASN · fallos distribuidos en ventana corta.

## Flujo de agentes
`soc-casemanager → soc-triage-l1 → soc-hunter-kql → soc-riskscorer → soc-remediator → soc-approver → soc-reporter`

## Evidencia requerida
IPs origen · cantidad de usuarios atacados · códigos de error · país/ciudad · app objetivo ·
comparación semanal · usuarios con login exitoso posterior.

## KQL

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 50126
| summarize Attempts=count(), Users=dcount(UserPrincipalName), UserList=make_set(UserPrincipalName, 20) by IPAddress, Location
| where Users >= 5 or Attempts >= 20
| order by Attempts desc
```

## Remediación (DryRun → aprobación)
Bloquear IP por Named Location/CA si corresponde · revisar usuarios con éxito posterior ·
forzar reset solo sobre usuarios con evidencia de compromiso · revisar MFA y métodos ·
crear alerta de seguimiento. Foco: distinguir spray sin éxito (LOW/MEDIUM) de spray con login
exitoso posterior (escalada vía BEC).

# Playbook: M365_DEVICE_CODE_PHISHING

Gap conocido Geonosis: CA de bloqueo device-code estuvo en **report-only** → expuesto a Kali365.

## Disparadores
- `AuthenticationProtocol = deviceCode`.
- Sign-ins deviceCode desde ubicaciones no esperadas.
- CA de bloqueo en `report-only` (no enforced).
- Usuario en riesgo posterior al evento.

## Flujo de agentes
`soc-casemanager → soc-triage-l1 → soc-forense-l2 → soc-hunter-kql → soc-riskscorer → soc-remediator → soc-approver → soc-reporter → soc-posture-advisor`

## KQL

```kql
SigninLogs
| where TimeGenerated > ago(14d)
| where AuthenticationProtocol =~ "deviceCode"
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, Location, ConditionalAccessStatus, ResultType
| order by TimeGenerated desc
```

## Remediación (DryRun → aprobación)
Enforce CA para bloquear device-code flow cuando no sea requerido · revocar sesiones de afectados ·
revisar apps consentidas · aplicar MFA phishing-resistant a administradores.

> El cambio de CA es estructural → lo recomienda `soc-posture-advisor` y se aplica gobernado,
> no por la IA interactiva.

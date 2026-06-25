# Playbook: M365_OAUTH_CONSENT

OAuth app consent sospechoso.

## Disparadores
- Consentimiento nuevo a app desconocida.
- Permisos Graph de alto impacto.
- Publisher no verificado.
- Consentimiento por usuario privilegiado.

## Flujo de agentes
`soc-casemanager → soc-forense-l2 → soc-hunter-kql → soc-riskscorer → soc-remediator → soc-approver → soc-reporter`

## Evidencia requerida
AppId · DisplayName · Publisher · permisos concedidos · usuario que consintió · fecha/hora ·
actividad posterior de la app/SP.

## KQL

```kql
CloudAppEvents
| where TimeGenerated > ago(30d)
| where ActionType has_any ("Consent to application", "Add app role assignment grant to user", "Add OAuth2PermissionGrant")
| project TimeGenerated, AccountDisplayName, ActionType, Application, RawEventData
| order by TimeGenerated desc
```

## Remediación (DryRun → aprobación)
Revocar grant sospechoso · bloquear app · revisar actividad del usuario que otorgó consentimiento ·
restringir user consent si no está gobernado.

> Si el service principal figura en `config/crown-jewels.json` como cuenta protegida o con roles admin,
> no bloquear/eliminar su grant sin aprobación humana explícita.

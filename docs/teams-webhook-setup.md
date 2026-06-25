# Teams webhook (Power Automate Workflows) — Geonosis SOC AI

El runbook publica en Teams con el formato de **mensaje + Adaptive Card**:

```json
{ "type": "message",
  "attachments": [
    { "contentType": "application/vnd.microsoft.card.adaptive",
      "content": { "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                   "type": "AdaptiveCard", "version": "1.4", "body": [ ... ] } } ] }
```

Esto es el formato de **Workflows** (Power Automate), NO el del viejo Office 365 Connector (retirado por Microsoft). Hay que crear un flujo "cuando se recibe una solicitud de webhook → publicar tarjeta en el canal".

## Pasos (vía la app Teams)

1. Elegí el **canal destino** del reporte (ej: `SOC / Geonosis SOC AI`). Si no existe, crealo.
2. En Teams: clic en los `…` del canal → **Workflows** (o desde la app **Power Automate** → *Create* → *Instant cloud flow*).
3. Buscá la plantilla **"Post to a channel when a webhook request is received"**
   (ES: *"Publicar en un canal cuando se recibe una solicitud de webhook"*).
4. *Next* → confirmá la conexión (tu cuenta o, mejor, una cuenta de servicio).
5. Elegí **Team** y **Channel** destino. *Create flow*.
6. Se crea el flujo con un trigger **"When a Teams webhook request is received"**. Abrilo y **copiá la URL del trigger** (`HTTP POST URL`). Esa es la URL que va a la variable.

## Cargar la URL en Azure Automation

```powershell
Set-AzAutomationVariable -ResourceGroupName 'siem' -AutomationAccountName 'aa-geonosis-soc-ai' `
  -Name 'GeonosisSocAi-TeamsWebhook' -Value '<URL-DEL-TRIGGER>' -Encrypted $true
```

## (Opcional) Ajustar el flujo para renderizar la card recibida

La plantilla por defecto suele publicar la tarjeta que llega en el body. Si publica texto plano en vez de la card:

1. En el flujo, acción **"Post card in a chat or channel"** (o *"Post adaptive card in a channel"*).
2. En el campo **Adaptive Card**, poné una expresión que tome la card del payload:
   `triggerBody()?['attachments']?[0]?['content']`
3. Guardá.

## Probar (desde tu PC, con el formato real del runbook)

```powershell
$webhook = '<URL-DEL-TRIGGER>'
$card = @{
  type = 'message'
  attachments = @(@{
    contentType = 'application/vnd.microsoft.card.adaptive'
    content = @{
      '$schema' = 'http://adaptivecards.io/schemas/adaptive-card.json'
      type = 'AdaptiveCard'; version = '1.4'
      body = @(
        @{ type='TextBlock'; size='Large'; weight='Bolder'; text='Geonosis SOC AI — TEST' },
        @{ type='TextBlock'; isSubtle=$true; text=('Generado: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm')) },
        @{ type='TextBlock'; wrap=$true; text='Si ves esto en el canal, el webhook funciona.' }
      )
    }
  })
}
Invoke-RestMethod -Method Post -Uri $webhook -ContentType 'application/json' -Body ($card | ConvertTo-Json -Depth 12)
```

Si la tarjeta aparece en el canal → listo. Esa misma URL la usa `Send-SocTeams`.

## Notas

- **Cuenta de servicio**: el flujo corre bajo la identidad de quien lo crea. Si lo creás con tu usuario y te vas, el flujo muere. Usá una cuenta de servicio/licenciada para producción.
- **Licencia**: Workflows básico viene con M365; flujos premium requieren licencia Power Automate (este no la necesita).
- El detalle completo del reporte va por **email** (HTML). La card de Teams es solo el resumen ejecutivo.

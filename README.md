# Geonosis SOC AI

SOC automation toolkit for small Microsoft 365 / Entra ID environments.

The project combines deterministic PowerShell/KQL detections with an optional AI narrative layer to produce weekly security reports, critical-change alerts and assisted incident-response workflows.

It is designed for the common "solo admin / small IT team" scenario: Microsoft 365 Business Premium, Defender, Sentinel or Log Analytics, Intune, and a need to reduce manual console-hopping without giving an AI uncontrolled write access.

## What It Does

- Builds a weekly SOC report from Microsoft Sentinel, Defender XDR, Entra ID and Intune signals.
- Sends executive-friendly summaries by email and Microsoft Teams.
- Detects high-value changes such as high-risk users, device-code phishing exposure, password spray, OAuth consent risk, Sentinel coverage gaps and posture drift.
- Keeps state between runs to compare week-over-week changes.
- Deduplicates critical alerts so unchanged conditions do not spam the administrator.
- Provides Claude Code subagents and playbooks for assisted triage, hunting, scoring, remediation planning and reporting.

## Architecture

```text
Azure Automation runbook
  -> Managed Identity
  -> Microsoft Graph / Defender XDR / Sentinel / Log Analytics
  -> deterministic KQL and PowerShell modules
  -> optional Azure OpenAI or Anthropic narrative
  -> Teams + email + normalized SOC inbox

Claude Code agents
  -> agents-soc/inbox
  -> case manager
  -> triage / forensics / KQL hunting / Intune context
  -> risk scoring
  -> dry-run remediation plan
  -> human approval gate
  -> executive + technical report
```

## Repository Layout

```text
config/
  settings.example.json       # copy to settings.json and fill your tenant values
  crown-jewels.example.json   # copy to crown-jewels.json and define protected assets
src/
  Invoke-GeonosisSocAi.ps1    # runbook entrypoint
  modules/                    # detection, observability, reporting, AI, hygiene
  kql/                        # versioned hunting queries
  templates/                  # email/report templates
deploy/
  Deploy-GeonosisSocAi.ps1    # Azure Automation deployment helper
  Grant-GraphRoles.ps1        # Graph/Defender app-role grants for the managed identity
.claude/agents/
  soc-*.md                    # Claude Code subagents
agents-soc/
  playbooks/                  # M365 incident playbooks
  contracts/                  # schemas for agent input/output
  scoring/                    # deterministic risk model
  ingest/                     # import normalized alerts from Automation
  inbox/                      # runtime alerts, ignored by Git
  cases/                      # runtime evidence/cases, ignored by Git
docs/
  architecture and operating documentation
```

## Quick Start

1. Clone the repository.

2. Create local configuration files:

```powershell
Copy-Item .\config\settings.example.json .\config\settings.json
Copy-Item .\config\crown-jewels.example.json .\config\crown-jewels.json
```

3. Edit `config/settings.json`:

- `tenantId`
- Sentinel / Log Analytics workspace name, ID, subscription and resource group
- Azure OpenAI endpoint/deployment or Anthropic fallback settings
- Teams/email delivery settings
- trusted egress IPs for password-spray noise reduction

4. Edit `config/crown-jewels.json`:

- break-glass accounts
- privileged roles/groups
- sensitive service principals
- critical cloud resources
- management/deployment endpoints

5. Deploy the Azure Automation account and variables:

```powershell
.\deploy\Deploy-GeonosisSocAi.ps1 `
  -SubscriptionId "<subscription-id>" `
  -ResourceGroup "<resource-group>" `
  -AutomationAccount "aa-soc-ai" `
  -Location "brazilsouth" `
  -SkipGraph
```

6. Grant Microsoft Graph and Defender app roles to the managed identity from a clean PowerShell 7 session:

```powershell
pwsh -NoProfile -File .\deploy\Grant-GraphRoles.ps1 `
  -TenantId "<tenant-id>" `
  -MiObjectId "<managed-identity-object-id>"
```

7. Configure the Teams webhook variable:

```powershell
Set-AzAutomationVariable `
  -ResourceGroupName "<resource-group>" `
  -AutomationAccountName "aa-soc-ai" `
  -Name "GeonosisSocAi-TeamsWebhook" `
  -Value "<workflow-webhook-url>" `
  -Encrypted $true
```

## AI Providers

The preferred provider is Azure OpenAI with Managed Identity, because no API key needs to be stored in code. Anthropic remains as a fallback when `settings.ai.provider` is set accordingly and the `GeonosisSocAi-AnthropicKey` Automation variable exists.

The AI layer is intentionally advisory. It summarizes, prioritizes and prepares analysis. Sensitive actions are handled through dry-run remediation and human approval.

## Assisted SOC Agents

The `.claude/agents/soc-*.md` files define 10 project-scoped Claude Code agents:

- case manager
- L1 triage
- L2 forensics
- KQL hunter
- Intune context
- risk scorer
- remediator
- approver
- reporter
- posture advisor

See [agents-soc/README.md](agents-soc/README.md) and [agents-soc/SHARED-GUARDRAILS.md](agents-soc/SHARED-GUARDRAILS.md).

## Security Model

- Runtime evidence is ignored by Git: `agents-soc/cases/`, `agents-soc/inbox/`, local settings and generated reports.
- Remediation starts in `DryRun`.
- Password reset, session revoke, account disable, mailbox-rule removal, OAuth-grant removal, device isolation and Conditional Access changes require explicit human approval.
- Secrets are stored in Azure Automation encrypted variables, not in source code.
- Tenant IDs, workspace IDs, subscription IDs, protected accounts and crown jewels should stay in local ignored config files.

## Requirements

- PowerShell 7.2 for Azure Automation runbooks.
- Azure Automation with System-Assigned Managed Identity.
- Microsoft Sentinel or Log Analytics with relevant tables enabled.
- Defender XDR / Microsoft Graph permissions depending on enabled modules.
- Optional: Azure OpenAI resource with `Cognitive Services OpenAI User` granted to the managed identity.
- Optional: Claude Code for the interactive agent workflow.

## Status

This is an operational scaffold and learning project. It is useful as a starting point for small Microsoft 365 security operations, but every tenant must validate permissions, detection thresholds, privacy requirements and remediation guardrails before production use.

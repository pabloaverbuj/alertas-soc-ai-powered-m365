# D-ThreatIntel/Get-ThreatTrends.psm1
# M12 — Feeds de tendencias auto-actualizados: CISA KEV, MITRE ATT&CK, abuse.ch ThreatFox.
# (Threat Analytics de Defender se referencia desde el reporte; su API pública es limitada.)

$script:Feeds = @{
    CisaKev   = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
    ThreatFox = 'https://threatfox-api.abuse.ch/api/v1/'
    # MITRE ATT&CK Enterprise (STIX) — repo oficial mitre-attack/attack-stix-data
    AttackStix = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json'
}

function Get-ThreatTrends {
    [CmdletBinding()] param([int] $RecentDays = 14)

    $kev = Get-CisaKev -RecentDays $RecentDays
    $iocs = Get-ThreatFoxRecent -Days $RecentDays
    return [pscustomobject]@{
        Summary    = "Tendencias — KEV nuevos ($RecentDays d): $(@($kev).Count) · IOCs PhaaS/AiTM recientes: $(@($iocs).Count)"
        Kev        = $kev
        Iocs       = $iocs
    }
}

function Get-CisaKev {
    param([int] $RecentDays = 14)
    try {
        $data = Invoke-RestMethod -Uri $script:Feeds.CisaKev
        $cut  = (Get-Date).AddDays(-$RecentDays)
        $data.vulnerabilities | Where-Object { [datetime]$_.dateAdded -ge $cut } |
            Select-Object cveID, vendorProject, product, vulnerabilityName, dateAdded
    } catch { Write-Warning "[kev] $($_.Exception.Message)"; @() }
}

function Get-ThreatFoxRecent {
    param([int] $Days = 14)
    try {
        $body = @{ query = 'get_iocs'; days = $Days } | ConvertTo-Json
        # abuse.ch exige Auth-Key desde ~nov-2024. Variable opcional; sin key se omite el feed.
        $hdr = @{}
        $key = Get-SocSecret -Name 'GeonosisSocAi-AbuseChKey'
        if ($key) { $hdr['Auth-Key'] = $key } else { Write-Warning "[threatfox] Sin GeonosisSocAi-AbuseChKey - feed omitido."; return @() }
        $resp = Invoke-RestMethod -Method Post -Uri $script:Feeds.ThreatFox -Headers $hdr -Body $body -ContentType 'application/json'
        # Filtra a familias relevantes para M365/cloud (PhaaS / AiTM)
        $resp.data | Where-Object { $_.malware_printable -match 'Phish|EvilProxy|Tycoon|AiTM|Kali365' } |
            Select-Object ioc, ioc_type, malware_printable, first_seen, confidence_level
    } catch { Write-Warning "[threatfox] $($_.Exception.Message)"; @() }
}

Export-ModuleMember -Function Get-ThreatTrends

PUT kbn:api/detection_engine/rules
{
  "enabled": true,

  "rule_id": "6eb2cff4-100e-474c-a008-c1e56c857257",
  "author": [ "lr2t9iz" ],
  "index": [ ".fleet-agents-*" ],
  "type": "query",
  "language": "kuery",
  "query": """ last_checkin >= "now-59m" AND last_checkin <= "now-15m" """,

  "name": "Elastic Agent Disconnected",
  "description": """Detects when a SIEM agent stops sending logs for more than 15 minutes.
This could indicate connectivity issues, agent misconfigurations, or potential tampering.""",
  "severity": "high",
  "risk_score": 89,
  "tags": [
    "OS: Windows",
    "OS: Linux"
  ],
  "references": [
    "https://github.com/netero1010/EDRSilencer"
  ],
  "false_positives": [
    "Network outages",
    "Agent intentionally disabled for maintenance"
  ],
  "setup": """## Setup
### Windows
```
Stop-Service Elastic Agent
Start-Service Elastic Agent
```
### Linux
```
sudo systemctl stop elastic-agent
sudo systemctl start elastic-agent

sudo service elastic-agent stop
sudo service elastic-agent start
```""",
  "note": """## Triage and analysis
Check Fleet Agents (Status: Offline)""",
  "max_signals": 100,
  "from": "now-3840s",
  "interval": "5m",
  "meta": {
    "from": "59m"
  },
  "rule_name_override": "local_metadata.host.hostname",
  "timestamp_override": "last_checkin",
  "related_integrations": [
    {
      "package": "elastic_agent",
      "version": "^1.5.2"
    }
  ],
  "required_fields": [
    {
      "name": "local_metadata.host.hostname",
      "type": "text"
    }
  ]
}
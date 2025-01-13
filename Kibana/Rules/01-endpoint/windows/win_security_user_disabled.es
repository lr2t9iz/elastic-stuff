POST kbn:api/detection_engine/rules
{
  "enabled": true,

  "rule_id": "957539b0-578b-4b66-97cc-c15809151a71",
  "author": [ "lr2t9iz" ],
  "index": [ ".ds-logs-system.security-*" ],
  "type": "query",
  "language": "kuery",
  "query": """ event.code: "4725" """,

  "name": "Windows User Account Disabled",
  "description": """When a user account is disabled in Active Directory, event ID 4725 gets logged.""",
  "severity": "high",
  "risk_score": 89,
  "tags": [ "OS: Windows" ],
  "references": [ "https://www.manageengine.com/products/active-directory-audit/account-management-events/event-id-4725.html/" ],
  "false_positives": [ ],
  "setup": """## Setup""",
  "note": """## Triage and analysis""",
  "max_signals": 100,
  
  "from": "now-135s",
  "interval": "2m",
  "meta": {
    "from": "15s"
  },
  
  "threat": [
    {
      "framework": "MITRE ATT&CK",
      "tactic": {
        "id": "TA0040",
        "name": "Impact",
        "reference": "https://attack.mitre.org/tactics/TA0040"
      }
    }
  ]
}
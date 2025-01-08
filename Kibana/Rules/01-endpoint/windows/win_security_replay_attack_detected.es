# "https://github.com/SigmaHQ/sigma/blob/bd2a4c37efde5f69f87040173e990f1f6ff9e234/rules/windows/builtin/security/win_security_replay_attack_detected.yml"

POST kbn:api/detection_engine/rules
{
  "enabled": true,

  "rule_id": "5a44727c-3b85-4713-8c44-4401d5499629",
  "author": [ "lr2t9iz" ],
  "index": [ ".ds-logs-system.security-*" ],
  "type": "query",
  "language": "kuery",
  "query": """ event.code: "4649" """,

  "name": "Windows Replay Attack Detected",
  "description": """Detects possible Kerberos Replay Attack on the domain controllers when "KRB_AP_ERR_REPEAT" Kerberos response is sent to the client.""",
  "severity": "high",
  "risk_score": 89,
  "tags": [ "OS: Windows" ],
  "references": [ "https://github.com/Yamato-Security/EnableWindowsLogSettings/blob/7f6d755d45ac7cc9fc35b0cbf498e6aa4ef19def/ConfiguringSecurityLogAuditPolicies.md", "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4649"
  ],
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
        "id": "TA0006",
        "name": "Credential Access",
        "reference": "https://attack.mitre.org/tactics/TA0006"
      },
      "technique": [
        {
          "id": "T1558",
          "name": "Steal or Forge Kerberos Tickets",
          "reference": "https://attack.mitre.org/techniques/T1558",
          "subtechnique": [ ]
        }
      ]
    }
  ]
}
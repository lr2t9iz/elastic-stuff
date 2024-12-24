PUT kbn:api/detection_engine/rules
{
  "enabled": true,

  "rule_id": "a3e699cf-f86d-4ea7-b15b-0d3d99b0428e",
  "author": [ "lr2t9iz" ],
  "index": [ ".ds-logs-system.security-*" ],
  "type": "query",
  "language": "kuery",
  "query": """
(
    event.code: "4720"
) AND NOT (
    user.name: ("ANONYMOUS LOGON" OR "other_user_exception")
)
""",

  "name": "Windows User Account Creation",
  "description": """
Identifies attempts to create a Windows User Account. This is sometimes done by attackers to persist or increase access to a system or domain.
Detects local user creation on Windows servers, which shouldn't happen in an Active Directory environment. Apply this Sigma Use Case on your Windows server logs and not on your DC logs.
  """,
  "severity": "high",
  "risk_score": 89,
  "tags": [ "OS: Windows" ],
  "references": [
    "https://raw.githubusercontent.com/elastic/detection-rules/refs/heads/main/rules/windows/persistence_user_account_creation_event_logs.toml",
    "https://raw.githubusercontent.com/SigmaHQ/sigma/refs/heads/master/rules/windows/builtin/security/win_security_user_creation.yml",
    "https://patrick-bareiss.com/detecting-local-user-creation-in-ad-with-sigma/"
  ],
  "false_positives": [
    "Legitimate local user creations may be done by a system or network administrator. Verify whether this is known behavior in your environment. Local user creations by unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.",
    "Domain Controller Logs",
    "Local accounts managed by privileged account management tools"
  ],
  "setup": """
## Setup
""",
  "note": """
## Triage and analysis
""",
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
        "id": "TA0003",
        "name": "Persistence",
        "reference": "https://attack.mitre.org/tactics/TA0003"
      },
      "technique": [
        {
          "id": "T1136",
          "name": "Create Account",
          "reference": "https://attack.mitre.org/techniques/T1136",
          "subtechnique": [
            {
              "id": "T1136.001",
              "name": "Local Account",
              "reference": "https://attack.mitre.org/techniques/T1136/001"
            },
            {
              "id": "T1136.002",
              "name": "Domain Account",
              "reference": "https://attack.mitre.org/techniques/T1136/002"
            }
          ]
        }
      ]
    }
  ],
  "related_integrations": [
    {
      "package": "elastic_agent",
      "version": "^2.0.3"
    }
  ],
  "required_fields": [
    {
      "name": "event.code",
      "type": "keyword",
      "ecs": true
    }
  ]
}
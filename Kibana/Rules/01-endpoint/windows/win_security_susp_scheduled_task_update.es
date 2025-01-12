# "https://github.com/SigmaHQ/sigma/blob/fad4742996c55d8d4663e611f84877a2b741dc46/rules/windows/builtin/security/win_security_susp_scheduled_task_update.yml"

POST kbn:api/detection_engine/rules
{
  "enabled": true,

  "rule_id": "614cf376-6651-47c4-9dcc-6b9527f749f4",
  "author": [ "lr2t9iz" ],
  "index": [ ".ds-logs-system.security-*" ],
  "type": "query",
  "language": "kuery",
  "query": """ event.code: "4702" AND message: (*cmd* OR *powershell* OR *pwsh* OR *wmic* OR *mshta* OR *cscript* OR *wscript* OR *scriptrunner* OR *bash* OR *regsvr32* OR *rundll32* OR *certutil* OR *bitsadmin* OR *scrcons* OR *forfiles* OR *hh* OR *temp* OR *roaming* OR *public* OR *desktop* OR *downloads* OR *programdata* OR perflogs*) """,

  "name": "Windows Suspicious Scheduled Task Update",
  "description": """Detects update to a scheduled task event that contain suspicious keywords.""",
  "severity": "high",
  "risk_score": 89,
  "tags": [ "OS: Windows" ],
  "references": [ "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4702" ],
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
        "id": "TA0002",
        "name": "Execution",
        "reference": "https://attack.mitre.org/tactics/TA0002"
      }
    },
    {
      "framework": "MITRE ATT&CK",
      "tactic": {
        "id": "TA0003",
        "name": "Persistence",
        "reference": "https://attack.mitre.org/tactics/TA0003"
      }
    },
    {
      "framework": "MITRE ATT&CK",
      "tactic": {
        "id": "TA0004",
        "name": "Privilege Escalation",
        "reference": "https://attack.mitre.org/tactics/TA0004"
      },
      "technique": [
        {
          "id": "T1053",
          "name": "Scheduled Task/Job: Scheduled Task",
          "reference": "https://attack.mitre.org/techniques/T1053",
          "subtechnique": [
            {
              "id": "T1053.005",
              "name": "Scheduled Task",
              "reference": "https://attack.mitre.org/techniques/T1053/005"
            }
          ]
        }
      ]
    }
  ]
}
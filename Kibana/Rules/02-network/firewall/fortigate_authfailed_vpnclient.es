POST kbn:api/detection_engine/rules
{
  "enabled": true,
  
  "rule_id": "2a32512a-a9f4-4704-8b85-394cd4070e0a",
  "author": [ "lr2t9iz" ],
  "index": [ ".ds-logs-fortinet_fortigate.log-*" ],
  "type": "threshold",
  "language": "kuery",
  "query": """ fortinet.firewall.subtype: "vpn" AND event.code: "0101037121" """,
  "threshold": {
    "field": [
      "fortinet.firewall.xauthuser",
      "fortinet.firewall.vpntunnel"
    ],
    "value": 8
  },

  "name": "FortiGate AuthFailed VPNClient",
  "description": """This rule detects multiple failed VPN authentication attempts (event code 0101037121) on Fortinet FortiGate firewalls. 
It triggers when the same user or VPN tunnel exceeds 8 failed attempts, helping identify potential unauthorized access attempts.""",
  "severity": "high",
  "risk_score": 89,
  "tags": [
    "Firewall",
    "FortiGate"
  ],
  "references": [],
  "false_positives": [],
  "setup": """## Setup
If the activity is deemed malicious, block the source IP address on the firewall, notify the user involved, and enforce a password reset if necessary.
Strengthen authentication mechanisms, such as enabling multi-factor authentication (MFA), and review VPN access policies.
Monitor for continued failed attempts from other IPs to identify potential distributed attacks.""",
  "note": """## Triage and analysis
Review the source IP address and user account associated with the failed VPN authentication attempts. 
Check if the source IP matches known or trusted addresses or if it appears in threat intelligence feeds. 
Determine if the activity is due to user error, such as incorrect credentials, or if it indicates a brute force or unauthorized access attempt.
Cross-reference related logs, such as successful logins or unusual activity from the same user or IP, for additional context.""",
  "max_signals": 100,
  
  "from": "now-1200s",
  "interval": "5m",
  "meta": {
    "from": "15m"
  }
}
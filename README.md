
# SOC Alert Investigation Playbook


### General Guidelines (Apply to All Alerts)
- **Triage:** Capture timestamp, affected entities (user, IP, hostname, account), severity, and quick enrichment (geoIP, reputation, UEBA baseline).
- **Validate:** True positive, false positive, or benign? Look for correlated events in ±24 hours.
- **Scope & Hunt:** Pivot on IOCs. Map to MITRE ATT&CK. Check for kill-chain progression (Initial Access → Execution → Persistence → Lateral → Exfil).
- **Containment:** Isolate host, disable account, block IP/domain as needed.
- **Tools:** SIEM correlation queries, EDR process trees/timelines, firewall/IDS logs, email sandbox, cloud audit logs (CloudTrail, Azure Activity, etc.).
- **Document & Learn:** Log findings, tune rules, and run proactive hunts for related TTPs.

---

## Alert Investigation Checklist

| Rule Name | Investigation Steps |
|-----------|---------------------|
| **Brute Force Login Detection** — Multiple failed sign-ins from one source. | 1. Extract source IP, failure count, targeted accounts, and timestamps.<br>2. Check IP reputation, geo-location, and firewall/IDS logs.<br>3. Correlate with any successful logins from same/related IPs.<br>4. Review post-login activity on successful accounts.<br>5. Block IP if malicious; force password reset + MFA re-enroll.<br>6. Hunt for similar patterns environment-wide. |
| **Password Spraying** — Common passwords tried across many accounts. | 1. Identify source IP(s) and list of targeted accounts (low-and-slow).<br>2. Check for successful authentications, especially admins.<br>3. Review email gateway for phishing vectors.<br>4. Enable smart lockout/conditional access.<br>5. Hunt for follow-on MFA fatigue or lateral movement. |
| **Suspicious Login from New Country** — Login from an unusual location. | 1. Verify IP geo, user agent, and device fingerprint vs. baseline.<br>2. Check for VPN/proxy or known travel.<br>3. Review historical logins for the user.<br>4. If suspicious: force global sign-out, reset password, review sessions. |
| **Impossible Travel** — Same account used too far apart too quickly. | 1. Calculate time/distance plausibility between logins.<br>2. Check device consistency and concurrent sessions.<br>3. Review OAuth tokens and granted apps.<br>4. Force sign-out + password reset if malicious. |
| **MFA Fatigue Attack** — Too many push prompts sent to one user. | 1. Review rapid successive MFA prompts in logs.<br>2. Correlate with login attempts and source IP.<br>3. Contact user out-of-band; deny pending prompts.<br>4. Recommend number matching or phishing-resistant MFA. |
| **Leaked Credential Usage** — Known compromised credentials were used. | 1. Confirm leak source via TI or breach databases.<br>2. Check successful usage and associated sessions.<br>3. Immediate password reset + MFA re-registration.<br>4. Scan endpoint for malware. |
| **Account Lockout Spike** — Unusual number of locked accounts. | 1. Correlate with brute force or spraying.<br>2. Identify source IPs and high-value targets.<br>3. Review UEBA scores for affected users.<br>4. Check post-lockout activity. |
| **Privilege Escalation Attempt** — User tried to gain higher permissions. | 1. Extract exact action (UAC bypass, sudo, token impersonation).<br>2. Analyze parent process in EDR.<br>3. Correlate with credential dumping or new admin creation.<br>4. Revert changes and investigate actor. |
| **New Admin Account Created** — Unexpected privileged account was added. | 1. Identify creator, source IP/device, and granted permissions.<br>2. Verify against change management ticket.<br>3. Scan for linked persistence.<br>4. Disable if unauthorized and investigate creator. |
| **Disabled Security Controls** — Security protection was turned off. | 1. Identify disabled component (EDR, logging, AV).<br>2. Review actor, method, and timing.<br>3. Check for related malware/persistence.<br>4. Re-enable immediately (high priority). |
| **Suspicious PowerShell Execution** — PowerShell ran in an attacker-like way. | 1. Extract and decode full command line.<br>2. Analyze parent/child processes and network connections.<br>3. Review script block logging (Sysmon/EDR).<br>4. Hunt for similar executions. |
| **Encoded Command Execution** — Obfuscated commands were executed. | 1. Fully decode Base64/XOR/obfuscation.<br>2. Review process tree and arguments.<br>3. Correlate with downloads or C2.<br>4. Hunt for other obfuscated activity. |
| **Malicious Macro Activity** — Office macro behavior looked unsafe. | 1. Review email gateway + attachment hash.<br>2. Check sandbox results and Office process tree.<br>3. Scan endpoint for dropped files.<br>4. User awareness if needed. |
| **Malware Detected** — Known malicious code was found. | 1. Confirm IOCs (hash, behavior) and EDR verdict.<br>2. Isolate host immediately.<br>3. Identify entry vector and lateral movement.<br>4. Full scan + reimage if required. |
| **Ransomware Behavior Detected** — File activity matched ransomware behavior. | 1. Assess encryption speed/volume and ransom notes.<br>2. Isolate host and segment network.<br>3. Verify offline backups.<br>4. Preserve evidence and identify initial access. |
| **Living-off-the-Land Tool Abuse** — Legitimate tools were used suspiciously. | 1. Analyze command lines (certutil, wmic, regsvr32, etc.).<br>2. Review process ancestry.<br>3. Hunt for other LOLBins.<br>4. Restrict via AppLocker/WDAC where possible. |
| **Persistence Mechanism Created** — A startup, task, or service was added. | 1. Review added item (Run key, scheduled task, service).<br>2. Check actor, binary signature, and path.<br>3. Remove and monitor for re-creation.<br>4. Hunt for similar persistence. |
| **Lateral Movement Detected** — Access spread to another internal host. | 1. Identify source/target hosts and method (RDP, SMB, WMI, PsExec).<br>2. Trace used credentials.<br>3. Review internal firewall logs.<br>4. Consider network segmentation. |
| **Remote Service Creation** — A remote service was created on a system. | 1. Review source, target, and service details.<br>2. Correlate with credential access.<br>3. Remove service and investigate. |
| **Credential Dumping Attempt** — Passwords or tokens may have been extracted. | 1. Check LSASS access or tools (Sysmon ID 10).<br>2. Look for pass-the-hash/ticket usage.<br>3. Enable Credential Guard/PPL.<br>4. Reset affected credentials. |
| **Suspicious Process Injection** — One process tried to inject into another. | 1. Review EDR/Sysmon injection events.<br>2. Analyze source/target processes.<br>3. Check for C2 or Cobalt Strike activity. |
| **Unsigned Binary Execution** — An untrusted executable was launched. | 1. Check file path, hash, and digital signature.<br>2. Review download source and process tree.<br>3. Block if malicious. |
| **DNS Tunneling Suspected** — DNS traffic looked like covert communication. | 1. Analyze query volume and patterns (encoded subdomains).<br>2. Identify responsible process.<br>3. Block domains and investigate implant. |
| **Command and Control Beaconing** — Repeated traffic matched C2 patterns. | 1. Extract beacon metadata (jitter, headers, URIs).<br>2. Identify process or injection.<br>3. Block C2 aggressively.<br>4. Hunt for additional beacons. |
| **Known Bad IP Connection** — Traffic matched a malicious IP. | 1. Review TI context and traffic direction.<br>2. Correlate all activity to/from the IP.<br>3. Block and investigate. |
| **Data Exfiltration Spike** — Unusual outbound data volume was seen. | 1. Quantify volume, destination, and data type.<br>2. Check for compression/encryption.<br>3. Review DLP logs.<br>4. Notify compliance if sensitive. |
| **Sensitive File Access** — Protected files were opened or copied unexpectedly. | 1. Identify user, files, and access method.<br>2. Correlate with privilege changes or exfil.<br>3. Review DLP events. |
| **DLP Policy Violation** — Sensitive data movement broke policy. | 1. Review violation details and destination.<br>2. Assess intent vs. malicious activity.<br>3. Remediate exposure. |
| **Unusual Cloud Storage Sharing** — Files were shared externally abnormally. | 1. Review sharing settings and actor.<br>2. Check post-share access logs.<br>3. Revoke external links. |
| **Suspicious OAuth Consent** — A risky app was granted access. | 1. Review requested permissions and creator.<br>2. Check app usage.<br>3. Revoke if risky. |
| **New API Key Created** — A new key was generated unexpectedly. | 1. Identify creator and usage.<br>2. Review API activity post-creation.<br>3. Rotate/revoke if unauthorized. |
| **Mailbox Rule Created** — A suspicious email rule was added. | 1. Review rule conditions (forwarding/deletion).<br>2. Check for BEC indicators.<br>3. Remove rule and investigate creator. |
| **Phishing Email Detected** — An email matched phishing indicators. | 1. Review gateway verdict, headers (SPF/DKIM/DMARC).<br>2. Check user actions (click/open).<br>3. Block similar emails. |
| **Malicious Attachment Detected** — A harmful attachment was found. | 1. Review sandbox results and hash.<br>2. Analyze endpoint process tree.<br>3. Scan for execution/persistence. |
| **Suspicious URL Clicked** — A user clicked a risky link. | 1. Review URL sandbox verdict.<br>2. Check endpoint follow-on activity.<br>3. Block domain/IP. |
| **USB Device Inserted** — A removable device was connected. | 1. Review device details and user.<br>2. Scan USB/endpoint for malware.<br>3. Enforce USB restrictions. |
| **Sensitive Data on USB** — Protected data was copied to USB. | 1. Identify copied files and user.<br>2. Review DLP logs.<br>3. Scan involved devices. |
| **Tamper Attempt Detected** — Logging or security tools were targeted. | 1. Identify targeted controls and method.<br>2. Treat as critical (possible blinding).<br>3. Re-enable and investigate. |
| **Log Source Failure** — A telemetry source stopped sending logs. | 1. Check agent/collector status.<br>2. Investigate tampering or connectivity.<br>3. Restore visibility quickly. |
| **Policy Misconfiguration Detected** — A security control was changed unsafely. | 1. Review change details and actor.<br>2. Revert unsafe configuration.<br>3. Audit for malicious follow-on. |
| **Threat Intelligence Match** — An entity matched a known threat indicator. | 1. Review exact IOC and TI context.<br>2. Correlate with internal logs.<br>3. Enrich with additional intelligence. |
| **Gmail Phishing and Spam** — User-reported phishing or spam activity rose. | 1. Analyze reported emails and trends.<br>2. Correlate with gateway detections.<br>3. Update filters and training. |
| **Google Operations Alert** — Google reported a service-related security issue. | 1. Review Google Workspace/Security details.<br>2. Correlate with identity and cloud logs.<br>3. Apply recommended actions. |
| **Mobile Device Compromise** — A managed device showed compromise signs. | 1. Review MDM/EDR indicators (jailbreak, anomalous apps).<br>2. Remote wipe if confirmed.<br>3. Review corporate data access. |
| **Mandatory Service Announcement: Product** — Important product notice. | 1. Review vendor details.<br>2. Apply updates or config changes.<br>3. Escalate internally if needed. |
| **Mandatory Service Announcement: Security** — Important security notice. | 1. Prioritize patching and remediation.<br>2. Test changes where possible.<br>3. Verify post-remediation. |
| **Mandatory Service Announcement: Billing** — Important billing notice. | 1. Coordinate with finance team.<br>2. Check for unauthorized resource usage. |
| **Mandatory Service Announcement: Legal** — Important legal notice. | 1. Escalate to legal/compliance immediately.<br>2. Document all actions. |
| **Public Cloud Resource Exposure** — A cloud asset was publicly accessible. | 1. Review ACLs and exposure details.<br>2. Identify who made the change.<br>3. Revoke public access and scan for exfil. |
| **Overly Permissive Access Policy** — Cloud permissions were too broad. | 1. Audit IAM/policy changes.<br>2. Apply least-privilege fixes.<br>3. Review data access logs. |
| **Compliance Violation** — Activity or config broke policy rules. | 1. Review violation scope.<br>2. Remediate and notify compliance. |
| **Monitoring Gap / Log Source Failure** — Expected telemetry stopped flowing. | 1. Identify failed sources.<br>2. Restore agents/collectors.<br>3. Investigate potential tampering. |
| **Anomalous User Behavior** — User activity looked unusual. | 1. Review UEBA deviation details.<br>2. Correlate with other alerts.<br>3. Check for legitimate context (travel, role change). |
| **Suspicious File Transfer** — File movement or upload looked abnormal. | 1. Quantify files, destination, and volume.<br>2. Identify responsible user/app.<br>3. Check for exfil indicators. |
| **Data Breach Indicator** — Signs of unauthorized data exposure. | 1. Scope exposed data.<br>2. Notify legal/compliance/IR.<br>3. Contain and investigate root cause. |
| **Encoded PowerShell Download Cradle** — Encoded PowerShell fetched content. | 1. Decode full command.<br>2. Review downloaded payload and execution.<br>3. Hunt for similar cradles. |
| **Cobalt Strike HTTP Header Match** — Traffic resembled Cobalt Strike. | 1. Extract headers, URI patterns, and jitter.<br>2. Identify injected process or named pipes.<br>3. Block C2 and hunt for beacons. |
| **Unusual Privilege Change** — Permissions changed unexpectedly. | 1. Review exact change and actor.<br>2. Correlate with escalation activity.<br>3. Revert and audit. |
| **Unusual Command from Unknown IP** — Admin-like command came from an odd source. | 1. Review session type (RDP/SSH/web shell) and source.<br>2. Analyze full command context.<br>3. Investigate as potential compromise. |
| **Open Storage Bucket** — Cloud storage was left exposed. | 1. Review bucket ACLs and public settings.<br>2. Check access logs for unauthorized downloads.<br>3. Secure immediately and scan for exposure. |

---

**Notes**
- **Prioritization Order:** Ransomware, C2/Beaconing, Credential Dumping, New Admin Accounts, Tamper Attempts, Data Exfiltration, and Control Disabling should be handled first.
- **Automation:** Use SOAR playbooks for repetitive containment (account disable, host quarantine, password reset).
- **Proactive Hunting:** After investigating any alert, hunt for sibling TTPs across the environment.
- **False Positive Reduction:** Maintain allowlists for known good activity and regularly tune rules.



Last updated: April 2026  
Feel free to open an issue or suggest improvements!

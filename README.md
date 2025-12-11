🔍 Task 3 – Basic Vulnerability Scan on My PC
📌 Objective
The objective of this task is to perform a basic vulnerability scan on my personal computer using Nessus Essentials, identify security issues, analyze their severity, and document remediation steps.
This task is part of the Cyber Security Internship – Task 3.

🛠️ Tools Used
Nessus Essentials (Free Version)
A powerful vulnerability scanner used to detect security weaknesses, network misconfigurations, and outdated services.
🖥️ System Scanned
Operating System: Windows 11
Target IP: 192.168.56.1
Scan Type: Basic Network Scan
Scan Duration: ~8 minutes
Authentication: Not provided
📊 Scan Summary
Nessus identified the following:

Severity Level	Count
🔴 Critical	0
🟠 High	0
🟧 Medium	1
🟩 Low	0
🔵 Informational	Several
Only one medium-level vulnerability was found. The rest are informational findings, which are normal system responses.

🚨 Key Vulnerabilities Identified
🟧 1. SMB Signing Not Required (Medium • CVSS 5.3)
Description:
SMB traffic is not cryptographically signed, allowing possible Man-in-the-Middle (MITM) attacks.

Fix:
Enable SMB signing:

Group Policy:
Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options

powershell Copy code Enable:

Microsoft network server: Digitally sign communications (always)
Microsoft network client: Digitally sign communications (always)
PowerShell:
Set-SmbServerConfiguration –EnableSecuritySignature $true –Force
Set-SmbClientConfiguration –EnableSecuritySignature $true –Force
🔵 2. SSL/TLS Multiple Issues (Informational)
Description:
Older or weak TLS/SSL configurations detected.

Fix:

Disable SSL 2.0 / SSL 3.0

Disable TLS 1.0 / 1.1

Keep only TLS 1.2 and 1.3 enabled.

🔵 3. SMB Information Disclosure (Informational)
Description:
SMB service exposed internal metadata.

Fix:
Disable SMBv1 (outdated and insecure):

powershell
Copy code
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
🔵 4. HTTP/TLS Response Behavior (Informational)
Description:
HTTP/TLS responses leaked general service information.

Fix:
Disable IIS web service if not used:

powershell
Copy code
Stop-Service W3SVC
Set-Service W3SVC -StartupType Disabled
🖼️ Screenshots
<img width="1341" height="952" alt="Screenshot 2025-12-11 145351" src="https://github.com/user-attachments/assets/3a414fac-645d-4eae-a719-c3ac3a5353d1" />


Scan Summary

Vulnerability List

SMB Signing Issue

SSL/TLS Issues

Host Details

📄 Report File
A full detailed report has been included in:

👉 Windows-Vulnerability-Scan-Report.md

🧠 Learning Outcome
This task helped me understand:

How to run vulnerability scans

How Nessus Essentials works

How CVSS scoring is interpreted

How to analyze and remediate vulnerabilities

Basic Windows hardening techniques

✅ Conclusion
The system has no critical or high vulnerabilities.
Only one medium severity issue (SMB Signing) was found, along with several informational findings.

After applying the recommended fixes, the system’s security posture is improved and stable.

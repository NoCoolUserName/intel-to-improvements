# ActiveMQ to LockBit · limited derived case

The DFIR Report describes two intrusions through an exposed Windows ActiveMQ server vulnerable to CVE-2023-46604. The incident began in mid-February 2024; the second access followed 18 days later.

CertUtil downloaded a Metasploit payload. Java was the parent of command execution.

Malicious processes accessed LSASS memory. A privileged service account subsequently enabled lateral activity; its credential origin is an analyst assessment.

Remote services launched payloads on additional Windows hosts. Obfuscated PowerShell appeared in this activity.

AnyDesk was installed with an automatically starting service.

RDP sessions carried ransomware execution. Attribution to the established LockBit operation is not confirmed: the authors assess independent use of a leaked builder.

The report identifies 166.62.100[.]52 as C2 and an AnyDesk login address. A separate narrative section names 166.62.100[.]62; retain this discrepancy for review.

Advanced IP Scanner is a legitimate tool used during the intrusion; its hash alone is not a block recommendation.

Source-cited Sigma rules include 19b08b1c-861d-4e75-a1ef-ea0c1baf202b and 114e7f1c-f137-48c8-8f54-3088c24ce4b9.

Publisher case references: TB27524 and PR39767.

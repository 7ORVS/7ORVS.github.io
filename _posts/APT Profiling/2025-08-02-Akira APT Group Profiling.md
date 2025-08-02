---
title: "Akira APT Profiling"
classes: wide
header:
  teaser: /assets/images/site-images/Akira.jpg
ribbon: Black
description: "This report delves into Akira ransomware group"
categories:
  - APT Profiling
toc: true
---



## Overview
Since emerging in March 2023, the Akira ransomware group has targeted over 250 organizations across North America, Europe, and Australia, impacting a wide range of businesses and critical infrastructure. As of January 1, 2024, the group has reportedly extorted approximately $42 million in ransom payments. Initially focused on Windows systems, Akira’s early ransomware variant was written in C++ and appended the `.akira` extension to encrypted files. In April 2023, the group expanded its operations by developing a Linux variant targeting VMware ESXi virtual machines. By August 2023, Akira actors began deploying a new Rust-based variant called Megazord, which uses the `.powerranges` extension, and have since used Megazord, Akira, and an updated Akira_v2 variant interchangeably.  Like many attackers, Akira uses the ransomware to encrypt files after first breaking into a network and stealing data. This group also employs a double extortion tactic, demanding a ransom from victims in exchange for file decryption and not leaking stolen information to the public.

## Origin
Akira’s developers are likely based in Russia or other former Soviet states. Unlike many ransomware groups operating from Russian-speaking regions, Akira’s malware does not include functionality to terminate execution upon detecting a Russian keyboard layout. However, evidence suggests a Russian origin, as the group has been observed communicating in Russian on dark web cybercrime forums. Additionally, the victim profile—primarily organizations in the United States, United Kingdom, and Canada—further aligns with patterns seen in other Russian-speaking threat actor groups.
## Targeted sectors/countries
Akira targets many sectors from food production to manufacturing which indicates that the Akira ransomware group victimized any organizations they found vulnerable. But mostly they target these sectors and countries

![](/assets/images/apt-profiling/Akira/Akira-Targeted-Sectors.jpg)

![](/assets/images/apt-profiling/Akira/Akira-Targeted-Countries.jpg)

## Timeline

After reviewing Akira's activities since 2023 we can construct this timeline for its activities

| Year | Month     | Date Range                             | Total Victim Posts        |
| ---- | --------- | -------------------------------------- | ------------------------- |
| 2025 | August    | August 1, 2025                         | 5 separate organizations  |
| 2025 | July      | July 4, 2025 – July 30, 2025           | 31 separate organizations |
| 2025 | June      | June 11, 2025 – June 26, 2025          | 42 separate organizations |
| 2025 | May       | May 8, 2025 – May 21, 2025             | 30 separate organizations |
| 2025 | April     | April 2, 2025 – April 30, 2025         | 32 separate organizations |
| 2025 | March     | March 4, 2025 – March 25, 2025         | 45 separate organizations |
| 2025 | February  | February 2, 2025 – February 28, 2025   | 31 separate organizations |
| 2025 | January   | January 6, 2025 – January 31, 2025     | 44 separate organizations |
| 2024 | December  | December 9, 2024 – December 27, 2024   | 54 separate organizations |
| 2024 | November  | November 12, 2024 – November 29, 2024  | 72 separate organizations |
| 2024 | October   | October 1, 2024 – October 4, 2024      | 11 separate organizations |
| 2024 | September | September 3, 2024 – September 26, 2024 | 21 separate organizations |
| 2024 | August    | August 1, 2024 – August 21, 2024       | 6 separate organizations  |
| 2024 | July      | July 1, 2024 – July 31, 2024           | 32 separate organizations |
| 2024 | June      | June 3, 2024 – June 28, 2024           | 21 separate organizations |
| 2024 | May       | May 1, 2024 – May 31, 2024             | 21 separate organizations |
| 2024 | April     | April 4, 2024 – April 30, 2024         | 18 separate organizations |
| 2024 | March     | March 1, 2024 – March 29, 2024         | 17 separate organizations |
| 2024 | February  | February 1, 2024 – February 28, 2024   | 16 separate organizations |
| 2024 | January   | January 8, 2024 – January 31, 2024     | 27 separate organizations |
| 2023 | December  | December 1, 2023 – December 25, 2023   | 17 separate organizations |
| 2023 | November  | November 7, 2023 – November 30, 2023   | 19 separate organizations |
| 2023 | October   | October 4, 2023 – October 31, 2023     | 13 separate organizations |
| 2023 | September | September 6, 2023 – September 29, 2023 | 9 separate organizations  |
| 2023 | August    | August 1, 2023 – August 31, 2023       | 31 separate organizations |
| 2023 | July      | July 5, 2023 – July 28, 2023           | 17 separate organizations |
| 2023 | June      | June 1, 2023 – June 29, 2023           | 26 separate organizations |
| 2023 | May       | May 1, 2023 – May 30, 2023             | 39 separate posts         |
| 2023 | April     | April 29, 2023                         | 9 posts                   |

### Observations from the timeline and victims nature :

#### **Spikes in activity** noted in:
- **November 2024** (72 posts)
- **December 2024** (54 posts)
- **March 2025** (45 posts)
- **January 2025** (44 posts)
- **June 2025** (42 posts)
These surges may align with ransomware affiliate incentives, end-of-quarter extortion pushes, or recruitment periods.

#### **Victim Location**
Based on company names, Akira primarily targets USA, Western countries, and South Africa 

#### **Types of targeted victims**
 Many organizations are **small to medium enterprises (SMEs)** rather than Fortune 500 companies.
Indicates Akira favors **less protected environments**, likely with:    
- Less mature cybersecurity programs.
- Slower incident response capabilities.

#### **Strong capabilities and infrastructure**
Akira could exfiltrate 269 GB from one victim. This indicates that this group have a strong tooling, discipline, stealth, and infrastructure—all signs of a mature, well-funded, and highly capable threat actor Not just a smash-and-grab group.

## TTPs

| Tactic               | Technique Description                                        | MITRE ATT&CK ID | Description                                                                                                                                                     |
| -------------------- | ------------------------------------------------------------ | --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Initial Access       | Valid Accounts                                               | T1078           | Uses compromised VPN credentialsl                                                                                                                               |
| Initial Access       | External Remote Services                                     | T1133           | The use of external-facing services such as Remote Desktop Protocol (RDP)                                                                                       |
| Initial Access       | Exploit Public-Facing Application                            | T1190           | Exploiting known Cisco vulnerabilities                                                                                                                          |
| Persistence          | Create Account: Domain Account                               | T1136.002       | Once initial access is established, Akira operators will create a domain account on the compromised system.                                                     |
| Persistence          | Create Account: Local Account                                | T1136.001       |                                                                                                                                                                 |
| Privilege Escalation | Valid Accounts: Domain Accounts                              | T1078.002       | FBI identified Akira threat actors creating an administrative account                                                                                           |
| Execution            | Command and Scripting Interpreter: PowerShell                | T1059.001       | utilizes PowerShell commands to delete volume shadow copies (VSS) on Windows systems                                                                            |
| Defense Evasion      | Impair Defenses: Disable or Modify Tools                     | T1562.001       | Cybersecurity researchers have observed Akira threat actors using PowerTool to exploit the Zemana AntiMalware driver and terminate antivirus-related processes. |
| Defense Evasion      | Modify Registry                                              | T1112           |                                                                                                                                                                 |
| Credential Access    | OS Credential Dumping: LSASS Memory                          | T1003.001       | Akira threat actors also use credential scraping tools like Mimikatz and LaZagne to aid in privilege escalation                                                 |
| Discovery            | System Information Discovery                                 | T1082           | Uses PCHunter and SharpHound to gather system information                                                                                                       |
| Discovery            | Remote System Discovery                                      | T1018           | Uses Advanced IP Scanner and MASSCAN to discover remote systems                                                                                                 |
| Discovery            | Permission Groups Discovery: Domain Groups                   | T1069.002       | Using `net` Windows commands are used to identify domain controllers                                                                                            |
| Collection           | Archive Collected Data: Archive via Utility                  | T1560.001       | Leveraging tools such as FileZilla, WinRAR                                                                                                                      |
| Collection           | Exfiltration Over Alternative Protocol                       | T1048           | WinSCP, and RClone to exfiltrate data                                                                                                                           |
| Command & Control    | Remote Access Software                                       | T1219           | May use either AnyDesk, Radmin, Cloudflare Tunnel, MobaXterm, RustDesk, or Ngrok to gain remote access on targeted systems                                      |
| Command & Control    | Remote Services: Remote Desktop Protocol                     | T1021.001       |                                                                                                                                                                 |
| Lateral Movement     | Lateral Tool Transfer                                        | T1570           | Uses RDP to move laterally within the victim’s network                                                                                                          |
| Exfiltration         | Exfiltration Over Web Service: Exfiltration to Cloud Storage | T1567.002       | Uses RClone to exfiltrate stolen information over web service                                                                                                   |
| Exfiltration         | Exfiltration Over Unencrypted Non-C2 Protocol                | T1048.003       | Uses FileZilla or WinSCP to exfiltrate stolen information via FTP                                                                                               |
| Impact               | Inhibit System Recovery                                      | T1490           | Deletes shadow copies to inhibit recovery                                                                                                                       |
| Impact               | Data Encrypted for Impact                                    | T1486           | Akira ransomware is used to encrypt files                                                                                                                       |



## DLS Tour

Akira is online on 2 sites on Dark web

| Onion Address                                                  | Site type |
| -------------------------------------------------------------- | --------- |
| akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion | DLS       |
| akiralkzxzq2dsrzsrvbr2xgbbu2wgsmxryd4csgfameg52n7efvr2id.onion | Chat      |

![](/assets/images/apt-profiling/Akira/Akira-DLS.png)
![](/assets/images/apt-profiling/Akira/Akira-Chat.png)

The DLS site is a terminal-like site, which lets you pass commands to view what you want.
The Leaks option allows you to view all victims affected by Akira, and it's available to download their leaked data. The data is downloaded as a `.torrent` file. Torrent files aren't the actual files; they're just a collection of links that a torrent client uses.

![](/assets/images/apt-profiling/Akira/Akira-Victim.png)

On news option, they talking about their upcoming leaks, they specify the company name and the size of leaked data.

![](/assets/images/apt-profiling/Akira/Akira-Message.png)

You can send them message also with contact option
## Exploited CVEs / Tools

#### Tools 

| Discovery           | C2                | Defense Evasion                 | Credential Theft | OffSec      | Networking | Exfiltration |
| ------------------- | ----------------- | ------------------------------- | ---------------- | ----------- | ---------- | ------------ |
| Advanced IP Scanner | AnyDesk           | PowerTool                       | DonPAPI          | Cloudflared | OpenSSH    | FileZilla    |
| Masscan             | MobaXterm         | Zemana Anti-Rootkit driver      | LaZagne          | -           | Ngrok      | MEGA         |
| ReconFTW            | Radmin            | KillAV (Terminator from GitHub) | Mimikatz         | -           | -          | RClone       |
| SharpHound          | RustDesk          | -                               | Impacket         | -           | -          | Temp[.]sh    |
| SoftPerfect NetScan | Cloudflare Tunnel | -                               | -                | -           | -          | WinSCP       |


#### CVEs

| Vendor     | Product                | CVE              | Source                          |
|------------|------------------------|------------------|----------------------------------|
| Cisco      | ASA & FTD              | CVE-2023-20269   | cisco.com                        |
| Cisco      | ASA & FTD              | CVE-2023-20263   | blog.talosintelligence.com      |
| Cisco      | ASA & FTD              | CVE-2020-3259    | cisa.gov                         |
| Fortinet   | FortiOS                | CVE-2022-40684   | stairwell.com                    |
| Fortinet   | FortiOS                | CVE-2019-6693    | stairwell.com                    |
| Fortinet   | FortiClient            | CVE-2023-48788   | blog.talosintelligence.com      |
| SonicWall  | SonicOS SSL-VPN        | CVE-2024-40766   | arcticwolf.com                   |
| Veeam      | Backup & Replication   | CVE-2024-40711   | @SophosXOps                      |
| Veeam      | Backup & Replication   | CVE-2023-27532   | sophos.com                       |
| VMware     | ESXi                   | CVE-2024-37085   | microsoft.com                    |
| VMware     | vSphere Client         | CVE-2021-21972   | qualys.com                       |


## References

- https://www.ransomware.live/group/akira
- https://www.ransomlook.io/group/akira
- https://www.s-rminform.com/latest-thinking/ransomware-in-focus-meet-akira
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a
- https://dailydarkweb.net/akira-ransomware-group-continues-attack-spree-allegedly-compromising-12-companies-in-72-hours/
- https://www.fortinet.com/blog/threat-research/ransomware-roundup-akira
- https://tinyhack.com/2025/03/13/decrypting-encrypted-files-from-akira-ransomware-linux-esxi-variant-2024-using-a-bunch-of-gpus/
- https://www.hhs.gov/sites/default/files/akira-randsomware-analyst-note-feb2024.pdf
- https://www.linkedin.com/posts/threatmon_akira-ransomware-group-ugcPost-7277859919427440640-M6lZ/?utm_source=share&utm_medium=member_desktop&rcm=ACoAACirI1gB2hCH3I_dvQp0NmW-JckJIkZK9NE
  
  
  
  
  
  

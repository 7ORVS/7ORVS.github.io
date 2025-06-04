---
title: "NightSpire APT Profiling"
classes: wide
header:
  teaser: /assets/images/site-images/NightSpire.jpg
ribbon: Black
description: "This report delves into NightSpire's tactics, infrastructure, and the implications of their activities"
categories:
  - Tutorials Summaries
toc: true
---


## Unmasking NightSpire: A New Threat in the Ransomware Landscape

In the ever-evolving world of cyber threats, a new player has emerged: NightSpire. First spotted in early 2025, this ransomware group has quickly garnered attention for its aggressive tactics and rapid expansion. Unlike some seasoned threat actors, NightSpire appears to be relatively new to the scene, yet it has already made a significant impact by targeting small to medium-sized businesses across various sectors, with a notable focus on manufacturing . Their operations involve a double extortion strategy—encrypting victim data and threatening to publish it on their dark web leak site if ransoms aren't paid. This report delves into NightSpire's tactics, infrastructure, and the implications of their activities, aiming to shed light on this emerging threat and provide insights for organizations to bolster their cybersecurity defenses.

## Emergence Timeline
- **Early March 2025**: First appearance on the cybercrime scene
- **March 12, 2025**: Dark web Data Leak Site (DLS) went live
- **March 14, 2025**: Recruitment post by xdragon128 on BreachForums seeking a "negotiation specialist"
- **Late April 2025**: Expanded global reach with victims across multiple countries

## Operational Infrastructure
- **Communication Channels**:
  - ProtonMail
  - OnionMail
  - Telegram
  - Gmail (showing operational security weaknesses)

  ![](/assets/images/tutorials-summaries/NightSpire/NightSpire-Mail.jpeg)


- **Data Leak Site (DLS)**:
  - Onion-based portal for double extortion strategy
  - "Databases" section listing company names, breach dates, data sizes
  - Countdown timers for scheduled public disclosures
  - "We say" page for naming and shaming non-paying victims

  
  ![](/assets/images/tutorials-summaries/NightSpire/NightSpire-About.jpeg)

  ![](/assets/images/tutorials-summaries/NightSpire/NightSpire-Victims.jpeg)

## Known Associated Operators
1. **xdragon128** (also known as Xdragon333)
   - Known malware developer
   - Previously linked to other threat groups in 2024:
     - Paranodeus
     - CyberVolk
     - DarkAssault

2. **cuteliyuan**
   - Operator associated with both NightSpire and earlier Rbfs ransomware group

## Possible Affiliations
- Evidence suggests NightSpire may be a rebrand of the earlier, low-profile **Rbfs ransomware group**


## Targeted Regions
Global reach spanning multiple countries including:
- United States
- Canada
- France
- Brazil
- Japan
- Egypt
- United Kingdom
- India
- South Korea
- Argentina
- Many others

## Targeted Sectors
- Healthcare
- Education
- Automotive
- Manufacturing (primary focus)
- Government and law enforcement
- Finance
- Construction
- Technology
- Retail
- Logistics

## Egyptian Targets

Egypt has been explicitly identified as a target country for NightSpire operations by CYFIRMA's Weekly Intelligence Report dated April 25, 2025. However, no specific campaign details unique to Egypt have been publicly disclosed in the available sources. Egypt appears to be part of NightSpire's broader global targeting strategy rather than the subject of a unique campaign.

After reviewing the DLS, I found that there’s 2 Egyptian victims for this APT:

- INI invesment
- Future Association for Microfinance

## Key Findings

1. Primary initial access vector is exploitation of CVE-2024-55591 in FortiOS (CVSS 9.6)
2. Ransomware is written in Go language and specifically targets OneDrive cloud storage
3. Group employs double extortion tactics with data exfiltration via MEGACmd and WinSCP
4. Technical indicators include .nspire file extension and readme.txt ransom notes
5. Associated with multiple infostealers: Azorult, Lumma, RedLine, and Vidar

## Detialed information

### Malware Characteristics

- **File Type**: Portable executable written in Go
- **Execution Behavior**: Creates console window using conhost.exe
- **Encryption Marker**: Appends .nspire extension to encrypted files
- **Ransom Note**: Creates readme.txt in directories with encrypted files

![](/assets/images/tutorials-summaries/NightSpire/NIghtSpire-Ransom-Message.jpeg)

![](/assets/images/tutorials-summaries/NightSpire/NightSpire-Ransome-Twit.jpeg)

### Attack Chain

1. **Initial Access**: Exploitation of CVE-2024-55591 in FortiOS
2. **Discovery**: Systematic enumeration of files and directories using Everything.exe
3. **Collection**: Data compression using 7-Zip before exfiltration
4. **Exfiltration**: Data transfer to MEGA cloud storage using MEGACmd or WinSCP
5. **Impact**: Encryption of files with .nspire extension, including OneDrive cloud storage

## Technical Indicators of Compromise (IOCs)

### File Indicators

- Files with **.nspire** extension (encrypted files)
- **readme.txt** ransom notes in directories with encrypted files
- Specific encrypted files observed:
  - C:\Users\Default\NTUSER.nspire
  - C:\Users\Default\NTUSER.DAT.nspire
  - C:\Users\RDhJ0CNFevzX\AppData\Local\Microsoft\CLR_v4.0\UsageLogs\powershell.exe.nspire
  - C:\Users\Public\*\desktop.nspire

### Process Indicators

- Suspicious conhost.exe execution
- Execution of WinSCP or MEGACmd with unusual parameters
- Execution of known infostealer malware (Azorult, Lumma, RedLine, Vidar)
- Suspicious PowerShell execution patterns

### Network Indicators

- Communications with Tor network (for leak site access)
- MEGA cloud storage traffic (for data exfiltration)
- FortiOS exploitation attempts targeting CVE-2024-55591
- IP address: 14.139.185[.]60 (associated with C2 infrastructure)

### Host Indicators

- Unauthorized administrative accounts
- Modified FortiOS configurations
- Presence of .nspire encrypted files
- readme.txt ransom notes
- Suspicious registry modifications

### Hash Values

- 35cefe4bc4a98ad73dda4444c700aac9f749efde8f9de6a643a57a5b605bd4e7 (Everything.exe)
- e275b8a02bf23b565bdaabadb220b39409eddc6b8253eb04e0f092d697e3b53d (v7.exe "Ransomware")

## MITRE ATT&CK Techniques

| Tactic                | Technique ID | Technique Name                         | Implementation                                        |     |
| --------------------- | ------------ | -------------------------------------- | ----------------------------------------------------- | --- |
| Resources Development | T1587        | Develop Capabilitie                    | Develop their own Go ransomware                       |     |
| Initial Access        | T1190        | Exploit Public-Facing Application      | Exploitation of CVE-2024-55591 in FortiOS             |     |
| Execution             | T1059        | Command and Scripting Interpreter      | Command-line execution via conhost.exe                |     |
| Execution             | T1072        | Software Deployment Tools              | Abuse of legitimate software tools                    |     |
| Persistence           | T1136        | Create Account                         | Creation of administrative accounts post-exploitation |     |
| Persistence           | T1547        | Boot or Logon Autostart Execution      | Ensures persistence across reboots                    |     |
| Privilege Escalation  | T1068        | Exploitation for Privilege Escalation  | Leverages super-admin access on FortiOS               |     |
| Defense Evasion       | T1036        | Masquerading                           | Use of legitimate tools and LOLBins                   |     |
| Discovery             | T1057        | Process Discovery                      | Enumeration of running processes                      |     |
| Discovery             | T1082        | System Information Discovery           | Collection of system details                          |     |
| Discovery             | T1083        | File and Directory Discovery           | Systematic enumeration of files and directories       |     |
| Collection            | T1119        | Automated Collection                   | Automated gathering of sensitive data                 |     |
| Collection            | T1560        | Archive Collected Data                 | Compression of data before exfiltration               |     |
| Command and Control   | T1071        | Application Layer Protocol             | Use of standard web protocols for C2                  |     |
| Exfiltration          | T1048        | Exfiltration Over Alternative Protocol | Use of encrypted channels for data exfiltration       |     |
| Exfiltration          | T1567.002    | Exfiltration to Cloud Storage          | Use of MEGACmd for data exfiltration                  |     |
| Impact                | T1486        | Data Encrypted for Impact              | Encryption of files with .nspire extension            |     |

## CVE-2024-55591 Technical Details

The primary initial access vector for NightSpire is CVE-2024-55591, a critical authentication bypass vulnerability in FortiOS and FortiProxy:

- **Affected Versions**: 
  - FortiOS 7.0.0 through 7.0.16
  - FortiProxy 7.0.0 through 7.0.19
  - FortiProxy 7.2.0 through 7.2.12

- **Vulnerability Details**:
  - Authentication bypass in Node.js websocket module
  - Allows unauthenticated remote attackers to gain super-admin privileges
  - Exploited by sending crafted requests to the Node.js websocket module

- **Exploitation Method**:
  1. Attacker sends specially crafted POST request to `/api/v2/cmdb/`
  2. Request includes websocket upgrade headers
  3. Vulnerability in Node.js websocket module allows authentication bypass
  4. Attacker gains super-admin privileges on the device

- **Post-Exploitation Activities**:
  1. Creation of new administrative user accounts
  2. Modification of firewall configurations
  3. Configuration of SSL VPN settings for persistent access
  4. Use of the compromised firewall as a pivot point for lateral movement


## Resources :
- https://www.redhotcyber.com/en/post/nightspire-a-new-player-in-the-ransomware-landscape/#Conclusions_and_Final_Considerations
- https://cyble.com/threat-actor-profiles/nightspire-ransomware-group/
- https://www.vmray.com/analyses/_vt/e275b8a02bf2/report/overview.html
- https://www.s-rminform.com/latest-thinking/ransomware-in-focus-meet-nightspire
- https://www.redpacketsecurity.com/nightspire-ransomware-victim-ecoinside/
- https://www.sonicwall.com/blog/nightspire-ransomware-encrypts-onedrive-files
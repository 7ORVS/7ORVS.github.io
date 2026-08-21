---
title: "Payload Ransom Group Profiling"
classes: wide
header:
  teaser: /assets/images/site-images/payload.jpg
ribbon: Black
description: "This report delves into Payload ransomware group"
categories:
  - Threat Actor Profiling
toc: true
---


## Overview

Payload is a double-extortion ransomware operation, first observed publishing victims on its dark-leak site (DLS) on 2026-02-17, that has posted 73 victims through 2026-08-13. The group operates cross-platform (Windows and Linux) C/C++ malware with an operator-driven CLI, indicating hands-on-keyboard deployment following prior compromise rather than automated spread.

Victims span at least 20 countries and a broad range of sectors, with no single country or sector representing a clear majority of the confirmed victim set. Attribution to a specific nation-state or actor group is not currently supported by available evidence and should be treated as unresolved.

The malware sample demonstrates a mature defense-evasion toolkit — ETW patching, dynamic API resolution, anti-debug checks, and full event-log wiping — combined with standard ransomware impact behaviors (shadow-copy deletion, backup/DB service termination, file encryption). These behaviors map to 10+ MITRE ATT&CK techniques and provide concrete detection opportunities.

Both identified leak-site onion services are currently offline; the negotiation portal remains reachable. This may reflect infrastructure rotation, law-enforcement action, or routine operational gaps — insufficient evidence exists to distinguish between these at this time.

---
##  Information Sources and Confidence Levels

This report draws on: 
- direct static analysis of Windows malware sample
- the group's own dark-leak site content
- third-party OSINT trackers and vendor write-ups. 

- High confidence: directly observed in binary analysis or primary-source infrastructure (DLS, portal).
    
- Moderate confidence: consistent inference from available data, not independently verified.
    
- Low confidence: based on a single uncorroborated source, or an assessed hypothesis absent direct evidence.


---
## Origin

There are no sources for this information unless SOCRadar that claims this group is linked to Russia but, no corroborating technical evidence (infrastructure overlap, code lineage, language artifacts, operational timing) is available to this analysis to support or refute that claim.
(Low confidence - single uncorroborated source)

---
## Targeted countries/sectors

### Countries 

The source material lists the following countries as targeted: Germany, Switzerland, United States, Singapore, Philippines, Jordan, Egypt, South Africa, France, Italy, Turkey, Brazil, Japan, and Canada. This list was provided as an aggregate roster rather than mapped to individual victims, so per-country victim counts cannot be reliably derived from it; treating any single country as a primary target based on this list alone is not supported.

Egypt-specific finding: 6 of the 73 published victims (≈ 8%) are identifiable in the leak-post data as Egypt-linked entities. This is a real and worth-tracking cluster

#### Confirmed Egypt-Linked Victims

- 2026-02-17-sodic.com (SODIC – real estate)
- 2026-02-19-Grid Fine Finishes (GFF)
- 2026-04-03-United Finance Egypt
- 2026-04-08-El Wastani Petroleum Company (WASCO)
- 2026-04-16-orientalweavers.com (Oriental Weavers)
- 2026-04-20-Better House
(High confidence)

### Sectors

The source material lists five targeted sectors: 
- Manufacturing
- Professional Services
- Retail & E-Commerce
- Financial Services
- Energy & Utilities

(High confidence)

---
## Timeline

This group published first post on DLS on 2026-02-17 and that's also the compilation date that found on the Windows version of ransomware

![](/assets/images/apt-profiling/Payload/payload-first-post.jpg)

![](/assets/images/apt-profiling/Payload/Payload-win-comp-date.jpeg)


73 victims were posted between 2026-02-17 and 2026-08-13. The full dated list is provided in Appendix A. Monthly posting volume is summarized below (note: August figure is a partial month, through the 13th):

|                |                    |                                                                              |
| -------------- | ------------------ | ---------------------------------------------------------------------------- |
| **Month**      | **Victims Posted** | **Notes**                                                                    |
| Feb 2026       | 8                  | First DLS post (2026-02-17)                                                  |
| Mar 2026       | 16                 | Peak onboarding of the leak cadence                                          |
| Apr 2026       | 18                 | Highest single month of activity                                             |
| May 2026       | 9                  | ~50% drop from April; 14-day gap (Apr 29 → May 13)                           |
| Jun 2026       | 12                 | Partial rebound                                                              |
| Jul 2026       | 5                  | 18-day gap (May 21 → Jun 8) preceded this slowdown; further gaps within July |
| Aug 1–13, 2026 | 5                  | 14-day gap (Jul 20 → Aug 3); both DLS/portal onion services now offline      |

Observed pattern: activity climbed from the group's Feb 2026 debut to a peak in April, then declined markedly from May onward, with three multi-week gaps (Apr 29–May 13, May 21–Jun 8, Jul 20–Aug 3). Both leak-post and file-server onion services are currently offline while the negotiation portal remains reachable.

Confidence: Moderate. Multiple explanations are plausible — infrastructure migration, d__isruption/takedown activity, affiliate attrition, or simply irregular posting cadence common to smaller RaaS-adjacent crews.

---
## Dark Leak Site Infrastructure

| **Onion Address**                                              | **Purpose**               | **Status**                 |
| -------------------------------------------------------------- | ------------------------- | -------------------------- |
| payloadrz5yw227brtbvdqpnlhq3rdcdekdnn3rgucbcdeawq2v6vuyd.onion | Leak site (posts)         | Offline at time of writing |
| payloadynyvabjacbun4uwhmxc7yvdzorycslzmnleguxjn7glahsvqd.onion | Negotiation / chat portal | Online at time of writing  |
| payload6eualw6kni6v2lqn7ovjcl76ojx25z5unsyvqo3lbqy3bo5qd.onion | File server               | Offline at time of writing |

The group's negotiation portal displays a Tox support ID and explicit statements disclaiming political motivation and RaaS affiliation.
#### Chat portal login page 

![](/assets/images/apt-profiling/Payload/Chat-portal.jpg)

---
## Attack Flow & TTPs

For initial access method, there's no confirmed information about how this group access the victim environment but from basic sample analysis, the ransomware run with args and the malware parse these args in the beginning of its code to determine pre-encryption activities.

![](/assets/images/apt-profiling/Payload/ransom-args.jpg)

| Flag          | Effect                                                                                  |
| ------------- | --------------------------------------------------------------------------------------- |
| `–background` | Runs encryption in the background (no console window); does NOT re-spawn itself         |
| `-m`          | Skips mutex creation/check (allows multiple instances)                                  |
| `-n`          | Does NOT write the ransom note to disk                                                  |
| `-d`          | Disables self-deletion                                                                  |
| `-k`          | Does NOT kill processes or stop services                                                |
| `-s`          | Skips network share enumeration (only local drives targeted)                            |
| `-l`          | Wipes all Windows Event Logs after encryption (anti-forensics)                          |
| `-i`          | Ignores filename filters (may re-encrypt its own files like notes or payload artifacts) |
| `–bypass-etw` | Patches ETW functions in `ntdll` to disable logging                                     |
| `–algo`       | Forces a specific ChaCha20 implementation (AVX2 or SSE2 optimized)                      |
| `–threads N`  | Sets number of worker threads for encryption                                            |
| `-p <path>`   | Encrypts only the specified path                                                        |
| `–log <path>` | Overrides default log file location                                                     |

These **14 flags** controls logging, encryption behavior, thread count, background execution, mutex handling, ransom note writing, service/process termination, ETW patching, and event log clearing.

The most realistic hypothesis we can assume that this group compromise the victim environment, perform persistence and back door, perform privilege escalation then run the ransomware manually with selected args.  

#### T1059.003 (Command and Scripting Interpreter: Windows Command Shell)

The ransomware executed via Windows CMD with needed args

#### T1480.002 (Execution Guardrails: Mutual Exclusion)

The malware create a mutex under the name `MakeAmericaGreatAgain` to avoid multiple execution

![](/assets/images/apt-profiling/Payload/mutex-creation.jpg)

#### T1027.007 (Obfuscated Files or Information: Dynamic API Resolution)

The malware dynamically resolve native APIs from ntdll.dll to conceal malicious functionalities and avoid static analysis

![](/assets/images/apt-profiling/Payload/native-apis.jpg)

#### T1685.005 (Disable or Modify Tools: Clear Windows Event Logs), T1070 (Disable or Modify Tools: Clear Windows Event Logs)

The malware clears the Windows event logs as an anti-forensics activities 

![](/assets/images/apt-profiling/Payload/Event-log-clearing.jpg)


The malware patches ETW functions to remove the activities tracing

![](/assets/images/apt-profiling/Payload/ETW-patching.jpg)

#### T1622 (Debugger Evasion)

The malware detect the debuggers via `IsDebuggerPresent`

![](/assets/images/apt-profiling/Payload/debugger-checking.jpg)

#### T1057 (Process Discovery)

The malware perform process discovery via `CreateToolhelp32Snapshot` to get and close the targeted processes during encryption phase.

![](/assets/images/apt-profiling/Payload/process-discovery.jpg)

#### T1082 (System Information Discovery)

The malware get the system information via calling the native API `NtQuerySystemInformation`

#### T1486 (Data Encrypted for Impact)

The malware encrypt the data on the target system with the extension `.payload` 
 
#### T1489 (Service Stop)

The malware terminate and stop multiple backup and database processes and services such as `sql.exe , veeam`

#### T1490 (Inhibit System Recovery)

The malware delete shadow copies that used to recovery via `vssadmin.exe`

![](/assets/images/apt-profiling/Payload/VSS-delete.jpg)

(High confidence - directly observed in binary analysis)

---
## IOCs & Detection recommendations

| IOCs                                                             | Notes                   |
| ---------------------------------------------------------------- | ----------------------- |
| 1ca67af90400ee6cbbd42175293274a0f5dc05315096cb2e214e4bfe12ffb71f | Malware Windows version |
| bed8d1752a12e5681412efbb8283910857f7c5c431c2d73f9bbc5b379047a316 | Malware Linux version   |
| MakeAmericaGreatAgain                                            | Mutex name              |
| C:\payload.log                                                   | Ransomware log file     |
| RECOVER_payload.txt                                              | Ransom Note             |

#### Ransom Note

```
Welcome to Payload!

The next 72 hours will determine certain factors in the life of your company:
the publication of the file tree, which we have done safely and unnoticed by all of you,
and the publication of your company's full name on our luxurious blog.
NONE of this will happen if you contact us within this time frame and our negotiations are favorable.

We are giving you 240 hours to:
1. familiarize yourself with our terms and conditions,
2. begin negotiations with us,
3. and successfully conclude them.
The timer may be extended if we deem it necessary (only in the upward direction).
Once the timer expires, all your information will be posted on our blog.

ATTENTION!
Contacting authorities, recovery agencies, etc. WILL NOT HELP YOU!
At best, you will waste your money and lose some of your files, which they will carefully take to restore!
You should also NOT turn off, restart, or put your computer to sleep.
In the future, such mistakes can make the situation more expensive and the files will not be restored!
We DO NOT recommend doing anything with the files, as this will make it difficult to recover them later!

When contacting us:
you can request up to 3 files from the file tree,
you can request up to 3 encrypted files up to 15 megabytes
so that we can decrypt them and you understand that we can do it.

First, you should install Tor Browser:
1. Open: https://www.torproject.org/download
2. Choose your OS and select it
3. Run installer
4. Enjoy!

In countries where tor is prohibited, we recommend using bridges,
which you can take: https://bridges.torproject.org/

You can read:
http://payloadrz5yw227brtbvdqpnlhq3rdcdekdnn3rgucbcdeawq2v6vuyd.onion (Tor)

To start negotiations, go to http://payloadynyvabjacbun4uwhmxc7yvdzorycslzmnleguxjn7glahsvqd.onion and login:
User: []
Password: [] 

Your ID to verify: [] 
```

### Detection recommendations

The following indicators and behaviors are recommended for detection engineering, in priority order:

- Mutex creation named “MakeAmericaGreatAgain” — high-fidelity, low false-positive indicator.
- Command-line execution of: cmd.exe /c vssadmin.exe delete shadows /all /quiet — monitor via process creation with full command-line logging (Sysmon EID 1 / Windows Security 4688).
- File creation events for RECOVER_payload.txt and mass file rename/creation with the .payload extension across multiple directories in a short window — indicative of active encryption.
- Windows Event Log clearing via EvtClearLog / wevtapi.dll calls, or the corresponding Security EID 1102 (“The audit log was cleared”) — correlate with any process outside expected admin tooling.
- Any process command line containing the documented flag set (--background, -m, -n, -d, -k, -s, -l, -i, --bypass-etw, --algo, --threads, -p, --log), especially --bypass-etw or -l in combination with any other flag.
- ETW provider tampering: unexpected VirtualProtect calls against ntdll.dll export addresses for EtwEventWrite / EtwEventWriteFull / EtwEventWriteTransfer / EtwRegister, where supported by EDR telemetry.
- Process termination targeting backup/DB services (sql.exe, veeam, and similar) shortly before mass file modification — useful as a pre-encryption early-warning signal.

## Conclusion 

Payload is a technically capable, human-operated double-extortion ransomware group active since at least February 2026, with 73 confirmed victims across a geographically and sectorally diverse set of organizations as of 2026-08-13. The malware demonstrates a deliberate, well-engineered defense-evasion toolkit and standard ransomware impact behaviors, both of which are High confidence and directly evidenced through binary analysis.

Attribution to any nation-state, and any single-country or single-sector primacy in targeting, are not currently supported by the available evidence and should not be asserted without additional corroboration. The group's posting cadence has slowed markedly since its April 2026 peak, and both of its identified leak/file-server onion services are currently offline; this is flagged for continued monitoring rather than treated as a conclusion about the group's operational status.

## References 

- https://www.ransomware.live/group/payload
- https://www.ransomlook.io/group/payload
- https://socradar.io/free-tools/ransomware-intelligence/groups/payload
- https://www.halcyon.ai/threat-group/payload#introduction
- https://www.egfincirt.org.eg/payload-ransomware/
- https://darkatlas.io/blog/behind-payload-in-depth-technical-analysis-of-payload-ransomware
# Sunburst
## Introduction

In March 2020, aorund 18,000 companies clicked on a pop-up link to update to the latest version of Orion, an IT performance monitoring platform.
Orion is developed by an American company, Solarwinds, that develop software to help businesses manage networks, systems and IT infrastructure.  
The attackers distributed a backdoor, called Sunburst, to these companies by compromising the Orion update system. 
When the companies clicked to update their software, they were installing a backdoor into their systems, allowing the hackers to gain access.

## Backdoor
`SolarWinds.Orion.Core.BusinessLayer.dll` is a SolarWinds digitally-signed component of the Orion software framework that contains a backdoor. 
This means the attacker was able to exploit the official update system deployed by SolarWinds so that companies saw a legitimate signature and trusted the update.
Official SolarWinds software will then unload and install the malicious .dll.
Once the software is deployed on a system, it is dormant for about 2 weeks (between 12-14 dqays) in an attempt to stay hidden and avoid detection.
After the two weeks, it executes commands called "Jobs" that allow it to do a variety of actions such as: transfer files, execute files, system profiling, machine reboots and service disabling.
The software will use obfuscated blocklists to identify AV tools and whether they're running as processes, services or drivers
It attempts to resolve a subdomain of `avsvmcloud(.)com` with the format of `<ENCODED VICTIM HOSTNAME>.appsync-api.{eu,us}-{west,east}-{1,2}.avsvmcloud[.]com`
The DNS response returns a CNAME record pointing towards a C2 domain. This traffic mimics normal SolarWinds API communcations

## More Technical Analysis (INCOMPLETE)

A troganised version of `SolarWinds.Orion.Core.BusinessLayer.dll` , a SolarWinds digitally signed plugin
Communicates via HTTP to third party servers
It stays hidden by imitating the Orion Improvement Program (OIP) and storing persistent state data inside legitimate plugin configuration files.
Other checks are performed in an attempt to evade detection by AV software such as: checking for analysis tools via process names, file write timestamps and AD domains.

Verifies process name is `solarwinds.businesslayerhost`. This was hidden in the source code by hashing the string and comparing to `17291806236368054941` (64-bit number). The hash is calculate using a standard FNV-1A (Fowler-Noll-Vo with reversed multiplication and XOR steps) 64-bit hash with an extra XOR using the 64-bit number, `6605813339339102567`. This extra hashing step means custom tools must be used to brute force. This algorithm is used often throughout the program.

The backdoor will onyl start if the filesystems last write time of `SolarWinds.Orion.Core.BusinessLayer.dll` is at least 12-14 days prior i.e. when the backdoor was installed. The named pipe `583da945-62af-10e8-4902-a8f205c72b2e` is created to ensure only one instance of the backdoor is running. If this pipe already exists, the malware exits. 

Repurpose `appSettings`, specifically `ReportWatcherRetry` and `ReportWatcherPostpone`. If `ReportWatcherRetry = 3` then the malware is deactivated. The backdoor can disable itself when its 'mission' is complete. This value can be checked by the investigation team to check if the malware is disabled. 

Check to see if system is connected to an AD domain and retrive the domain name. If the name matches one of the following, it will exit: `swdev.local, emea.sales, pci.local, apac.lab, swdev.dmz, cork.lab, saas.swi, dmz.local, lab.local, dev.local, lab.rio, lab.brno, lab.na, test, solarwinds` . This may be because these are internal SolarWinds domains that the attackers wanted to avoid.

Each string used by the software was embedded as a hash to disguise the string. These can be found [Here on FireEye's Github](https://github.com/fireeye/sunburst_countermeasures/blob/main/fnv1a_xor_hashes.txt)

## Splunk Detection and Protection
### Lookup Tables

Create lookup tables generated from the detected domains so far which can be found at the [FireEye Github](https://github.com/fireeye/sunburst_countermeasures) or [This Github Repo](https://github.com/rkovar/sunburstlookups)
From these, you can create searches to find hosts that have communicated with these domains. An example search might be:

`index=main sourcetype=stream:*
| lookup sunburstDOMAIN_lookup Domain AS query
| search isBad=TRUE
| stats VALUES(query) AS "Sunburst" by src_ip`

You can also identify IPs or hashes (again, the list can be found on Github)

### Azure AD

The attack may have targeted the Azure AD in an attempt to laterally move their privileges, either through Admin password or forged SAML tokens 
If you had connected your Azure data with Splunk (using the Microsoft Azure add-on for Splunk), you can use it to identify the route the attack may have taken.

### VPS

The malware may have used VPS's using an IP local to the country of the victim (although this is not confirmed with every case).
Use Splunk to review external to internal traffic (i.e malware VPS to internal network) and identify if any unknown IP's have accessed the internal system.

### Tstat

Often, quick searches are not enough and are unable to be scaled up enough, this is where `tstats` comes into play.
Example searches:

Find malicious domains in network resolution:

`| tstats summariesonly=true earliest(_time) as earliest latest(_time) as latest count as total_conn values(DNS.query) as query from datamodel=Network_Resolution where
    [| inputlookup sunburstDOMAIN_lookup
    | rename Domain as DNS.query
    | table DNS.query] OR DNS.query=*avsvmcloud.com by DNS.src DNS.vendor_product DNS.record_type DNS.message_type
| sort earliest
| eval earliest=strftime(earliest, "%c"), latest=strftime(latest, "%c")`

Find malicious IP addresses in network traffic

`| tstats summariesonly=true earliest(_time) as earliest latest(_time) as latest count as total_conn values(All_Traffic.dest) as dest from datamodel=Network_Traffic where
    [| inputlookup sunburstIP_lookup
    | rename IP as All_Traffic.dest
    | table All_Traffic.dest] by All_Traffic.src All_Traffic.vendor_product
| sort earliest
| eval earliest=strftime(earliest, "%c"), latest=strftime(latest, "%c")`

## Elastic

## QRadar

Abbreviation | Meaning
--- | ---
AD | Active Directory
API | Application Programming Interface
AV | Anti-Vrus
C2 | Command and Control
dll | Dynamic Linked Library
FNV | Fowler-Noll-Vo
IOC | Indicators of Compromise
OIP | Orion Improvemnt Program
SAML | Security Assertion Markup Language
SIEM | Security Information and Event Management
VPS | Virtual Private Server

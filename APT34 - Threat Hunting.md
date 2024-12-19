# Introduction

- PRIVATE INFORMATION

# Executive Summary

APT34 is a cyber espionage group with a nexus to Iran that has been
operational since at least 2014. We believe APT34 conducts operations
largely focused on phishing efforts to benefit Iranian nation-state
interests. This threat group has conducted broad targeting across a
variety of industries, including financial, government, energy,
chemical, and telecommunications, and has largely focused its operations
within the Middle East, but has targeted North American and European
organizations. We assess that APT34 works on behalf of the Iranian
government based on infrastructure details that contain references to
Iran, use of Iranian infrastructure, and targeting that aligns with
nation-state interests..

Cyberattacks by the group **Earth Simnavaz**, also known as **APT34 or
OilRig**. According to security researchers from Trend Micro, there has
been a significant increase in cyberattacks by this group targeting
critical sectors in the Gulf region, particularly in the United Arab
Emirates (VAE) and other Gulf countries1.

The primary objectives of these attacks are espionage and the theft of
sensitive information. The group employs various tools and techniques,
including the use of webshells to exploit vulnerable web servers and the
use of the Remote Monitoring and Management (RMM) tool ngrok to
obfuscate communication with their Command-and-Control (C2) servers1.

Reference:
https://www.trendmicro.com/en_us/research/24/j/earth-simnavaz-cyberattacks.html

Additionally, an email from the Cyber Threat Intelligence team at XXXXXXX
mentions that the XXXXXXXXXXXXXX, which includes information on
the **Earth Simnavaz attacks**, is shared within the OT Vulnerability- &
Incident-Management teams channel

- Mandiant analysts are constantly releasing new insights into adversary
  activity through our Mandiant Advantage platform. This report
  highlights new insights we have released over the past week on malware
  families we track.

- This report also includes information on how to access these insights
  immediately as they are released via our API and portal.

### Threat Detail

The initial point of entry for these attacks has been traced back to a
web shell uploaded to a vulnerable web server (Figure 1). This web shell
not only allows the execution of PowerShell code but also enables
attackers to download and upload files from and to the server, thereby
expanding their foothold within the targeted networks.

Once inside the network, the APT group leveraged this access to download
the ngrok remote management tool, facilitating lateral movement and
enabling them to reach the Domain Controller. During their operations,
the group exploited CVE-2024-30088 – the Windows Kernel Elevation of
Privilege vulnerability – as a means of privilege escalation, utilizing
an exploit binary that was loaded into memory via the open-source
tool RunPE-In-Memory.

This allowed them to register a password filter DLL, which subsequently
dropped a backdoor responsible for exfiltrating sensitive data through
the Exchange server. The exfiltrated data was relayed to a mail address
controlled by the threat actor, effectively completing the infection
chain and ensuring the attackers maintained control over the compromised
environment.

<img width="800" alt="image" src="https://github.com/user-attachments/assets/8f444389-16d5-4ef6-9673-72e8b98486c4">

source:
https://www.trendmicro.com/content/dam/trendmicro/global/en/research/24/j/earth-simnavaz-levies-advanced-cyberattacks/Simnavaz-Fig01.png

Earth Simnavaz has been known to leverage compromised organizations to
conduct supply chain attacks on other entities. We expected that the
threat actor could use the stolen accounts to initiate new attacks
through phishing against additional targets.  
  
There is also a documented overlap between Earth Simnavaz and another
APT group, FOX Kitten. In August, an alert from the Cybersecurity and
Infrastructure Security Agency (CISA) highlighted FOX Kitten's role in
enabling ransomware attacks targeting organizations in the US and the
Middle East. These threats should be taken seriously, as the potential
impact on compromised entities could be significant.

# Project Summary 

The purpose of this report is to perform Threat Hunting related to the
attack that occurred by incident **xxxxxxxxxxxxxxxxxx**, collecting the **IoCs** of these
attacks, **related malware**, **associated campaigns** and **associated
tools**, with the ultimate goal of integrating with Company tools doing
first verifying a possible exploitation attempt, if it occurs, carry out
the mitigation process and if it does not occur, supply the defense
sensors to raise the level of security.

# Threat Hunting

In this session you can find IoCs provided by **Trend Micro**.

 ![image](https://github.com/user-attachments/assets/e67deeca-bef7-4a67-93b0-62493e5aae51)


Below, you can find 34290 IoCs provided by Mandiant according APT34

 ![image](https://github.com/user-attachments/assets/dce8a153-f37b-4693-9935-c5ff6db20afb)

The second action was to investigate each **Associated Malware** and
collection more IoCs, however there is no associated name between this
new attack from Trend Micro researchers and Mandiant report.

Based on the I restrict the search based on two indicators

- **IC Score \> 50**

- **Last Seen = 2024**

Now, we have 191 IoCs to add in our External MISP

 ![image](https://github.com/user-attachments/assets/c86478f5-6255-4e84-b714-670560baccb9)


### Malware Family 

There are a large number of malware associated with this APTs Groups,
below you can find some references from APT 34 provided by Mandiant

<img width="800" alt="image" src="https://github.com/user-attachments/assets/631aeac5-c468-4723-949b-f781d41af094">

Source:
<https://advantage.mandiant.com/actors/threat-actor--beba5b2a-1ab1-5a42-904c-870c67bbf2f3#indicators>

### Hunting based on OSINT

Doing some OSINT search through the Malware Bazaar we can find some
binaries from this APTs group

<img width="850" alt="image" src="https://github.com/user-attachments/assets/6aba9830-ed58-4a9d-a003-d07cf191a81d">


There are two binaries in the Malware Bazaar repository where we can
collect more IoCs of this groups provided according to Trend Micro
Article.

#### **SHA256: 54e8fbae0aa7a279aaedb6d8eec0f95971397fea7fcee6c143772c8ee6e6b498**

 ![image](https://github.com/user-attachments/assets/9009fd52-1cd4-490c-9468-10753035234f)

<img width="800" alt="image" src="https://github.com/user-attachments/assets/527b7827-c310-45cd-9a00-ab9743da0617">


#### **SHA256: a24303234e0cc6f403fca8943e7170c90b69976015b6a84d64a9667810023ed7** 

 ![image](https://github.com/user-attachments/assets/4587a65f-c496-43fb-b004-10f70c3037e9)


<img width="850" alt="image" src="https://github.com/user-attachments/assets/cf5bb3be-ccab-4afc-9e75-03b6ff985d9b">


### Sandbox – JoeSandbox

We can find information from JoeSandbox based on:

**SHA256 =
54e8fbae0aa7a279aaedb6d8eec0f95971397fea7fcee6c143772c8ee6e6b498**

**Executable name = RunPEinMemory.exe**

<img width="850" alt="image" src="https://github.com/user-attachments/assets/94b59a95-6c36-41d0-ab00-2fd64f5ae179">


<img width="850" alt="image" src="https://github.com/user-attachments/assets/fbf4391e-c6b4-412d-8dfa-d79884e3988f">


<img width="850" alt="image" src="https://github.com/user-attachments/assets/ab7b07fc-3839-4cf1-a1c0-2ebb9dee22ef">


<img width="850" alt="image" src="https://github.com/user-attachments/assets/63027b41-89e1-416d-80be-abad99eff3c0">


<img width="850" alt="image" src="https://github.com/user-attachments/assets/62b76116-7d24-43f1-a8ef-5ee97d3ba3a4">

Source complete reference:
https://www.joesandbox.com/analysis/1533354/0/html

# YARA RULE

I didn’t find any specific YARA Rule for it, however I can create to add
in our EXT MISP

# Integration with MISP

Next step we can integrate this IoCs with our MISP using the Tags based
on Threat Actors ( APT Group) or Malware Family or Associated Campains.

<img width="800" alt="image" src="https://github.com/user-attachments/assets/f16250ac-4b31-42e6-affb-6b2760b495df" />


# Hunting Organization Tools

We can check with the SIEM team with we can any incident during the
latest 365 days

- EDR - XDR - Antivirus

- FW/IPS/WAF

- Other tools that you have.


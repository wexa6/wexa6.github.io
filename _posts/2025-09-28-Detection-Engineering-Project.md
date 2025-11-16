---
title: "Detection Engineering and Adversary Emulation"
date: 2025-09-28 10:00:00 +0200
categories: [Detection Engineering, Cybersecurity, SIEM]
tags: [elastic, siem, mitre att&ck, blue team]
image: /assets/img/detect/Detection cover.png
---

<h2 align="center">بِسْمِ اللَّهِ الرَّحْمَنِ الرَّحِيمِ</h2>

---

### Introduction

This project was a complete, end to end implementation of security detection use cases for a Windows Active Directory environment.  
The goal was simple, build reliable detection rules mapped to the MITRE ATT&CK framework, then validate each rule through real adversary simulation.

Everything was tested against real telemetry using Elastic SIEM, manual attack commands, and Atomic Red Team.

---

### Lab Environment

#### Core Components
- **Elastic SIEM** for log analysis and alerting  
- **Elastic Agent** on Windows 10 for collecting Security, System, PowerShell, and Sysmon logs  
- **Windows 10 VM** as the target  
- **Kali Linux VM** for manual attacker simulations  
- **Atomic Red Team** installed on Windows for MITRE technique emulation  

#### Methodology
1. Write a draft detection rule in KQL or EQL  
2. Simulate the attack using manual tools or Atomic Red Team  
3. Validate logs in Kibana Discover  
4. Fix audit policy gaps, log collection issues, and query errors  
5. Finalize and document each rule  

---

### Detection Use Cases

Below are the rules that were fully implemented and validated, each tied directly to a specific attacker behavior.

---

## 1. Reconnaissance  
### **User and Group Enumeration via net.exe and whoami.exe**

**Threat Scenario:** Attackers perform reconnaissance to map out the AD environment, identify privileged accounts, 
and plan lateral movement. This is often an initial step after gaining a foothold. 

![](/assets/img/detect/1.png){:width="550px"}

- **KQL:**
```
event.category: "process"
and event.type: "start"
and (process.name: "net.exe" or process.name: "whoami.exe")
```
![](/assets/img/detect/2.png)
![](/assets/img/detect/3.png)

---

## 2. Persistence  
### **Windows User Account Creation**

**Threat Scenario:** Attackers create new user accounts to establish a foothold in the environment, ensuring they have 
a way back in if their initial access method is discovered. 

![](/assets/img/detect/4.png)

- **KQL:**
```
winlog.event_id: 4720 or event.action: "user-created"
```
![](/assets/img/detect/5.png)
![](/assets/img/detect/6.png)

---

## 3. Privilege Escalation  
### **Privilege Escalation via net localgroup**

**Threat Scenario:** After creating an account, an attacker will escalate its privileges to gain administrative control over 
a machine, allowing them to disable security controls, access sensitive data, and move laterally.

![](/assets/img/detect/7.png)

- **KQL:**
```
winlog.event_id: 4732
and winlog.event_data.TargetUserName: "Administrators"
```
![](/assets/img/detect/8.png)
![](/assets/img/detect/9.png)

---

## 4. Credential Access  
### **Dumping the SAM Registry Hive**

**Threat Scenario:** Attackers dump credentials from the Security Account Manager (SAM) database to crack 
passwords offline. These credentials can then be used to access other systems and services across the network. 

- **KQL:**
```
process.name: "reg.exe"
and process.command_line: (*HKLM\SAM*)
```
![](/assets/img/detect/10.png)
![](/assets/img/detect/11.png)
![](/assets/img/detect/11.5.png)

---

## 5. Brute Force Detection (Correlation Rule)
### **Multiple Failed Logins Followed by a Success**

**Threat Scenario:** Attackers use automated tools like Hydra to try some password combinations against a user 
account, eventually guessing the correct one to gain remote access. (Here i used a kali linux machine to simulate the attack)

![](/assets/img/detect/12.png)

- **EQL:**
```
sequence by host.name, user.name with maxspan=10m
  [any where event.code == "4625"]
  [any where event.code == "4625"]
  [any where event.code == "4625"]
  [any where event.code == "4625"]
  [any where event.code == "4625"]
until [authentication where event.code == "4624"]
```
![](/assets/img/detect/13.png)
![](/assets/img/detect/14.png)



---

# Advanced Detection Engineering with Atomic Red Team

Atomic Red Team allowed me to test specific ATT&CK techniques cleanly and repeatedly.

Workflow:
1. Run Atomic Test (e.g. `Invoke-AtomicTest T1053.005`)  
2. Open Kibana Discover and inspect the raw telemetry  
3. Extract stable indicators and convert them into high confidence detection logic  

![](/assets/img/detect/15.png)

---

## 6. Persistence  
### **Scheduled Task Creation via schtasks.exe (T1053.005)**

**Threat Scenario:** Adversaries create scheduled tasks to automatically run their malicious code. This ensures their 
malware survives a system reboot, making it a cornerstone of persistence. 

![](/assets/img/detect/16.png)

- **KQL:**
```
process.name : "schtasks.exe" and process.args : "/create"
```
![](/assets/img/detect/19.png)
![](/assets/img/detect/17.png)
![](/assets/img/detect/18.png)

---

## 7. Defense Evasion  
### **Base64 or Encoded PowerShell Commands**

**Threat Scenario:**  Attackers encode their PowerShell commands using techniques like Base64 to hide malicious 
keywords (e.g., Invoke-Expression, Mimikatz) from basic security filters. 

![](/assets/img/detect/20.png)

**KQL:**
```
process.args : ("powershell.exe") and (
  process.args: *Base64* or
  process.args: *base64* or
  process.args: *encode* or
  process.args: *Encode*
)
```
![](/assets/img/detect/23.png)
![](/assets/img/detect/21.png)
![](/assets/img/detect/22.png)

---

### Conclusion

This project produced a complete set of validated detection rules and a stable workflow for continuous improvement.  
The biggest lesson was simple. Detection engineering is only real when you validate it with real logs and real attacks.
<!-- SCREENSHOT: Optionally add a screenshot of all rules listed in Elastic SIEM -->

| MITRE Tactic | Rule Name | Detection Logic |
|--------------|-----------|-----------------|
| Reconnaissance | User and Group Enumeration | Detects net.exe or whoami.exe process starts |
| Persistence | User Account Creation | Windows Event ID 4720 |
| Privilege Escalation | Add User to Administrators | Event ID 4732 with TargetUserName “Administrators” |
| Credential Access | SAM Dumping | reg.exe accessing HKLM\SAM |
| Credential Access | Brute Force Detection | 5x 4625 failures + 1x 4624 success |
| Persistence | schtasks.exe Persistence | schtasks.exe with /create |
| Defense Evasion | Encoded PowerShell | PowerShell with Base64 or encoding keywords |


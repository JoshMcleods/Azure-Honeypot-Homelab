# Azure Honeypot Homelab

![Azure](https://img.shields.io/badge/Azure-Cloud-blue)
![Windows](https://img.shields.io/badge/OS-Windows10-lightgrey)
![Sentinel](https://img.shields.io/badge/Sentinel-SIEM-orange)
![Logs](https://img.shields.io/badge/Logs-KQL-red)

A step-by-step guide to setting up a honeypot on Azure, collecting security logs, enriching them with geoIP data, and visualizing attacks in Microsoft Sentinel.  

This lab is designed for **educational purposes**, allowing you to simulate attacks, collect logs, and analyze attacker behavior in a safe environment.

---

## Table of Contents

1. [Setup Azure Subscription](#setup-azure-subscription)  
2. [Create the Honeypot VM](#create-the-honeypot-vm)  
3. [Logging into the VM and Inspecting Logs](#logging-into-the-vm-and-inspecting-logs)  
4. [Log Forwarding and KQL](#log-forwarding-and-kql)  
5. [Log Enrichment and Finding Location Data](#log-enrichment-and-finding-location-data)  
6. [Attack Map Creation](#attack-map-creation)  
7. [Notes](#notes)  
8. [License](#license)  

---

## Setup Azure Subscription

1. Create a free Azure subscription: [Azure Free Account](https://azure.microsoft.com/en-us/pricing/purchase-options/azure-account)  
2. Log in to the Azure Portal: [https://portal.azure.com](https://portal.azure.com)  

---

## Create the Honeypot VM

1. Go to **Virtual Machines** in the Azure portal.  
2. Create a **Windows 10 virtual machine**.  
   - Choose an appropriate size.  
   - Be mindful of the monthly cost if left on 24/7.  
   - Record the **username and password**.  
3. Configure the **Network Security Group** to allow **all inbound traffic**.  
4. Log into the VM and **disable the Windows firewall**:  
   - Open `wf.msc` → Properties → Turn all off.  

---

## Logging into the VM and Inspecting Logs

1. Fail 3 login attempts as `employee` (or another test username).  
2. Log into your VM.  
3. Open **Event Viewer** → Security Logs.  
4. Observe the 3 failed login attempts under **Event ID 4625**.  

Next: create a **central log repository** with **Log Analytics Workspace (LAW)**.

---

## Log Forwarding and KQL

1. Create a **Log Analytics Workspace**.  
2. Create a **Microsoft Sentinel** instance and connect it to the workspace.  
3. Configure the **Windows Security Events via AMA** connector.  
4. Create a **Data Collection Rule (DCR)** in Sentinel to watch for extension creation.  
5. Query logs using Kusto Query Language (KQL). Example:

SecurityEvent
| where EventId == 4625
Log Enrichment and Finding Location Data

Download the geoIP spreadsheet: geoIP-latLong.csv

In Sentinel, create a Watchlist:

Name/Alias: geoip

Source type: Local File

Number of lines before row: 0

Search Key: network

Allow the watchlist to fully import (~54,000 rows).

Enrich logs to show attacker locations:

let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where IpAddress == <attacker IP address>
    | where EventID == 4625
    | order by TimeGenerated desc
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents

Attack Map Creation

In Sentinel, create a new Workbook.

Delete prepopulated elements and add a Query element.

Go to the Advanced Editor tab and paste the JSON frommap.json 
Located https://github.com/JoshMcleods/Honeypot-Homelab 
Observe the query, map settings, and resulting Attack Map.

Notes

Always shut down or delete your VM when not in use to avoid Azure charges and delete repositories after to avoid charges

This lab is for educational purposes only. Do not use honeypots for unauthorized monitoring or attacks.

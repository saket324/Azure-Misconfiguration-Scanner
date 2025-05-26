# Azure-Misconfiguration-Scanner
Python script to detect common Azure security misconfigurations.

#  Azure Misconfiguration Scanner

##  Objective
Scan Azure environments for common security misconfigurations using Python and Azure SDKs.

##  What It Detects
- Public Blob containers
- Open inbound ports in Network Security Groups (NSGs)

##  How to Run
```bash
pip install -r requirements.txt
az login
python azure_misconfig_scanner.py

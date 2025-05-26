# MITRE ATT&CK Mapping

This project detects real-world cloud misconfigurations aligned with known attacker behaviors.

| Technique ID | Name                             | Detected By                                |
|--------------|----------------------------------|--------------------------------------------|
| T1580        | Cloud Infrastructure Discovery   | Public IP & Blob container exposure        |
| T1046        | Network Service Scanning         | NSG open inbound rule detection            |
| T1530        | Data from Cloud Storage Object   | Public Blob containers                     |
| T1082        | System Information Discovery     | NSG diagnostic logging audit               |
| T1562        | Impair Defenses                  | Missing NSG diagnostics                    |

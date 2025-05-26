# Azure MFA Misconfiguration Check

## Objective
Identify Azure AD users who do not have any MFA (multi-factor authentication) method configured.

## Command (Azure CLI)
```bash
az ad user list --query "[?strongAuthenticationMethods==null].{User:userPrincipalName}" --output table

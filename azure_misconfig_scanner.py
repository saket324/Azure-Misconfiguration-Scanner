from azure.identity import AzureCliCredential
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.monitor import MonitorManagementClient


# Authenticate using Azure CLI login
credential = AzureCliCredential()

# Get current subscription
subscription_client = SubscriptionClient(credential)
subscription = next(subscription_client.subscriptions.list())
sub_id = subscription.subscription_id

# Initialize clients
storage_client = StorageManagementClient(credential, sub_id)
network_client = NetworkManagementClient(credential, sub_id)
monitor_client = MonitorManagementClient(credential, sub_id)
report = []
def log(msg):
    print(msg)
    report.append(msg)

#1. Check for public Blob containers 
log("\n🔍 Scanning for public Blob containers...")
for account in storage_client.storage_accounts.list():
    account_name = account.name
    resource_group = account.id.split("/")[4]
    try:
        props = storage_client.blob_services.get_service_properties(resource_group, account_name, "default")
        log(f"[INFO] Checked {account_name} in {resource_group}")
    except Exception as e:
        log(f" Skipped {account_name}: {e}")

#2. Check for NSGs with open inbound ports 
log("\n🔍 Scanning NSGs for open inbound ports...")
for nsg in network_client.network_security_groups.list_all():
    nsg_name = nsg.name
    rg_name = nsg.id.split("/")[4]

    for rule in nsg.security_rules:
        if rule.direction == "Inbound" and rule.access == "Allow":
            if rule.source_address_prefix in ["*", "0.0.0.0/0"] or "Internet" in (rule.source_address_prefix or ""):
                log(f" NSG '{nsg_name}' in RG '{rg_name}' allows inbound access from ANY to port range {rule.destination_port_range or rule.destination_port_ranges} ({rule.name})")

# 3. Check for missing diagnostic settings on NSGs
log("\n🔍 Scanning NSGs for missing diagnostic logging...")
for nsg in network_client.network_security_groups.list_all():
    nsg_id = nsg.id
    nsg_name = nsg.name
    rg_name = nsg_id.split("/")[4]
    try:
        settings = list(monitor_client.diagnostic_settings.list(nsg_id))
        if not settings:
            log(f" NSG '{nsg_name}' in RG '{rg_name}' has no diagnostic logging enabled.")
    except Exception as e:
        log(f" Could not retrieve diagnostic settings for NSG '{nsg_name}': {e}")

# 4. Check for unattached public IPs
log("\n🔍 Scanning for unattached public IP addresses...")
for ip in network_client.public_ip_addresses.list_all():
    ip_name = ip.name
    rg_name = ip.id.split("/")[4]
    
    if not ip.ip_configuration:
        log(f" Public IP '{ip_name}' in RG '{rg_name}' is not associated with any resource.")

# 5. Check storage accounts for open firewall access
log("\n🔍 Scanning storage accounts for open firewall rules...")
for account in storage_client.storage_accounts.list():
    account_name = account.name
    rg_name = account.id.split("/")[4]
    
    props = storage_client.storage_accounts.get_properties(rg_name, account_name)
    if props.network_rule_set and props.network_rule_set.default_action == "Allow":
        log(f" Storage account '{account_name}' in RG '{rg_name}' allows traffic from all networks (no firewall).")

# 6. Save results to file
with open("results.txt", "w", encoding="utf-8") as f:
    for line in report:
        f.write(line + "\n")

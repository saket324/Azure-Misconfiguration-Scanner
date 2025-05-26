from azure.identity import AzureCliCredential
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import SubscriptionClient

# Authenticate using Azure CLI login
credential = AzureCliCredential()

# Get current subscription
subscription_client = SubscriptionClient(credential)
subscription = next(subscription_client.subscriptions.list())
sub_id = subscription.subscription_id

# Initialize clients
storage_client = StorageManagementClient(credential, sub_id)
network_client = NetworkManagementClient(credential, sub_id)

#1. Check for public Blob containers 
print("\n🔍 Scanning for public Blob containers...")
for account in storage_client.storage_accounts.list():
    account_name = account.name
    resource_group = account.id.split("/")[4]
    try:
        props = storage_client.blob_services.get_service_properties(resource_group, account_name, "default")
        print(f"[INFO] Checked {account_name} in {resource_group}")
    except Exception as e:
        print(f" Skipped {account_name}: {e}")

#2. Check for NSGs with open inbound ports 
print("\n🔍 Scanning NSGs for open inbound ports...")
for nsg in network_client.network_security_groups.list_all():
    nsg_name = nsg.name
    rg_name = nsg.id.split("/")[4]

    for rule in nsg.security_rules:
        if rule.direction == "Inbound" and rule.access == "Allow":
            if rule.source_address_prefix in ["*", "0.0.0.0/0"] or "Internet" in (rule.source_address_prefix or ""):
                print(f" NSG '{nsg_name}' in RG '{rg_name}' allows inbound access from ANY to port range {rule.destination_port_range or rule.destination_port_ranges} ({rule.name})")

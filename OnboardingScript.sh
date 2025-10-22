
export subscriptionId="a8cbb876-3c0b-41e0-914a-8b378aa251a1";
export resourceGroup="idstest01";
export tenantId="97ddd0b5-4ba0-4f0f-9887-6cc62ff2e6f6";
export location="eastus";
export authType="token";
export correlationId="c0d0d3ca-04e7-4cbb-8d25-93bb85e83abb";
export cloud="AzureCloud";


# Download the installation package
LINUX_INSTALL_SCRIPT="/tmp/install_linux_azcmagent.sh"
if [ -f "$LINUX_INSTALL_SCRIPT" ]; then rm -f "$LINUX_INSTALL_SCRIPT"; fi;
output=$(wget https://gbl.his.arc.azure.com/azcmagent-linux -O "$LINUX_INSTALL_SCRIPT" 2>&1);
if [ $? != 0 ]; then wget -qO- --method=PUT --body-data="{\"subscriptionId\":\"$subscriptionId\",\"resourceGroup\":\"$resourceGroup\",\"tenantId\":\"$tenantId\",\"location\":\"$location\",\"correlationId\":\"$correlationId\",\"authType\":\"$authType\",\"operation\":\"onboarding\",\"messageType\":\"DownloadScriptFailed\",\"message\":\"$output\"}" "https://gbl.his.arc.azure.com/log" &> /dev/null || true; fi;
echo "$output";

# Install the hybrid agent
bash "$LINUX_INSTALL_SCRIPT";
sleep 5;

# Run connect command
sudo azcmagent connect --resource-group "$resourceGroup" --tenant-id "$tenantId" --location "$location" --subscription-id "$subscriptionId" --cloud "$cloud" --tags 'secops=001,ArcSQLServerExtensionDeployment=Disabled' --correlation-id "$correlationId";

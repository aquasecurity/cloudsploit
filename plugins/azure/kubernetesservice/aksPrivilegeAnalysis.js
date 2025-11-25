module.exports = {
    title: 'Privilege Analysis',
    category: 'Kubernetes Service',
    domain: 'Containers',
    severity: 'Info',
    description: 'Ensures that AKS clusters and workloads are not granted excessive permissions.',
    more_info: 'AKS clusters often use managed identities to interact with Azure resources. Over-privileged identities can lead to privilege escalation or lateral movement within the cluster or the Azure environment. Following the principle of least privilege helps minimize potential attack surfaces.',
    link: 'https://docs.microsoft.com/en-us/azure/aks/use-managed-identity',
    recommended_action: 'Review and minimize Azure AD permissions granted to AKS managed identities and workload identities. Use Azure RBAC and Kubernetes RBAC best practices to ensure only required access is permitted.',
    apis: [''],
    realtime_triggers: [
        'Microsoft.ContainerService/managedClusters/write',
        'Microsoft.ContainerService/managedClusters/delete',
        'Microsoft.ContainerService/managedClusters/agentPools/write',
        'Microsoft.ManagedIdentity/userAssignedIdentities/assign/action',
    ],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        callback(null, results, source);
    },
};

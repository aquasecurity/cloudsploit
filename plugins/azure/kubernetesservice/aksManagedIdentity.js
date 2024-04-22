var async = require('async');

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'AKS Cluster Managed Identity Enabled',
    category: 'Kubernetes Service',
    domain: 'Containers',
    severity: 'Medium',
    description: 'Ensures a system or user assigned managed identity is enabled to authenticate to AKS Cluster.',
    more_info: 'Maintaining cloud connection credentials in code is a security risk. Credentials should never appear on developer workstations and should not be checked into source control. Managed identities for Azure resources provides Azure services with a managed identity in Azure AD which can be used to authenticate to any service that supports Azure AD authentication, without having to include any credentials in code.',
    recommended_action: 'Enable system or user-assigned identities for all AKS Clusters.',
    link: 'https://learn.microsoft.com/en-us/azure/aks/use-managed-identity',
    apis: ['managedClusters:list'],
    realtime_triggers: ['microsoftcontainerservice:managedclusters:write', 'microsoftcontainerservice:managedclusters:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.managedClusters, function(location, rcb) {

            var managedClusters = helpers.addSource(cache, source,
                ['managedClusters', 'list', location]);

            if (!managedClusters) return rcb();

            if (managedClusters.err || !managedClusters.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Kubernetes clusters: ' + helpers.addError(managedClusters), location);
                return rcb();
            }

            if (!managedClusters.data.length) {
                helpers.addResult(results, 0, 'No existing Kubernetes clusters found', location);
                return rcb();
            }

            managedClusters.data.forEach(managedCluster => {
                
                if (managedCluster.identity && managedCluster.identity.type) {
                    helpers.addResult(results, 0, 'AKS cluster has managed identity enabled', location, managedCluster.id);
                } else {
                    helpers.addResult(results, 2, 'AKS cluster does not have managed identity enabled', location, managedCluster.id);
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};

var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'AKS Encryption At Rest with BYOK',
    category: 'Kubernetes Service',
    domain: 'Containers',
    severity: 'High',
    description: 'Ensure that Azure Kubernetes cluster data is encrypted with CMK.',
    more_info: 'AKS Cluster allows you to encrypt your data using customer-managed keys (CMK) instead of using platform-managed keys, which are enabled by default. Your keys encrypt the backup data must be stored in Azure Key Vault.This provides you with full control over the data and the keys.',
    recommended_action: 'When creating a new Kubernetes Cluster, ensure that encryption at rest using CMK is enabled under the Node pool tab during creation.',
    link: 'https://learn.microsoft.com/en-us/azure/aks/azure-disk-customer-managed-keys',
    apis: ['managedClusters:list'],
    realtime_triggers: ['microsoftcontainerservice:managedclusters:write', 'microsoftcontainerservice:managedclusters:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

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
                helpers.addResult(results, 0, 'No existing Kubernetes clusters', location);
                return rcb();
            }

            for (let cluster of managedClusters.data) {
                if (!cluster.id) continue;
                
                if (!cluster.diskEncryptionSetID) {
                    helpers.addResult(results, 2, 'AKS cluster data is not encrypted using CMK', location, cluster.id);
                } else {
                    helpers.addResult(results, 0, 'AKS cluster data is encrypted using CMK', location, cluster.id);
                }
            }
            
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
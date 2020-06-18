var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Kubernetes RBAC Enabled',
    category: 'Kubernetes Service',
    description: 'Ensures that RBAC is enabled on all Azure Kubernetes Service instances',
    more_info: 'Role Based Access Control (RBAC) provides greater control and security for Kubernetes clusters and should be enabled on all instances.',
    recommended_action: 'Enable RBAC authentication for all Azure Kubernetes Clusters',
    link: 'https://docs.microsoft.com/en-us/azure/aks/aad-integration',
    apis: ['managedClusters:list'],

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

            managedClusters.data.forEach(managedCluster => {
                if (Object.prototype.hasOwnProperty.call(managedCluster, 'kubernetesVersion') && managedCluster.enableRBAC) {
                    helpers.addResult(results, 0, 
                        'RBAC is enabled on the cluster', location, managedCluster.id);
                } else {
                    helpers.addResult(results, 2, 
                        'RBAC is not enabled on the cluster', location, managedCluster.id);
                }
            });
            
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
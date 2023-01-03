var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'AKS Cluster Private',
    category: 'Kubernetes Service',
    domain: 'Containers',
    description: 'Ensures that Azure Kubernetes clusters are private.',
    more_info: 'In a private cluster, the control plane or API server has internal IP addresses that are defined in the RFC1918 - Address Allocation for Private Internet document. By using a private cluster, you can ensure network traffic between your API server and your node pools remains on the private network only.',
    recommended_action: 'Modify cluster network configuration and enable private cluster feature.',
    link: 'https://learn.microsoft.com/en-us/azure/aks/private-clusters',
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

            for (let cluster of managedClusters.data) {
                if (!cluster.id) continue;
                
                if (!cluster.apiServerAccessProfile || !cluster.apiServerAccessProfile.enablePrivateCluster) {
                    helpers.addResult(results, 2, 'AKS cluster is not private', location, cluster.id);
                } else {
                    helpers.addResult(results, 0, 'AKS cluster is private', location, cluster.id);
                }
            }
            
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
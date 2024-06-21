var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'AKS API Server Authorized IP Ranges',
    category: 'Kubernetes Service',
    domain: 'Containers',
    severity: 'Low',
    description: 'Ensures that Azure Kubernetes clusters have authorized IP ranges configured.',
    more_info: 'Specifying IP ranges improves the security of your clusters and minimizes the risk of attacks by limiting the IP address ranges that can access the API server. This helps ensure that only authorized users and systems can interact with your cluster, enhancing overall security posture.',
    recommended_action: 'Modify AKS clusters and configure authorized IP ranges.',
    link: 'https://learn.microsoft.com/en-us/azure/aks/api-server-authorized-ip-ranges',
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
                helpers.addResult(results, 0, 'No existing Kubernetes clusters found', location);
                return rcb();
            }

            for (let cluster of managedClusters.data) {
                if (!cluster.id) continue;

                if (cluster.apiServerAccessProfile && cluster.apiServerAccessProfile.authorizedIPRanges && cluster.apiServerAccessProfile.authorizedIPRanges.length){
                    helpers.addResult(results, 0, 'AKS cluster has authorized IP ranges configured for secure access to API server', location, cluster.id);
                } else {
                    helpers.addResult(results, 2, 'AKS cluster does not have authorized IP ranges configured for secure access to API server', location, cluster.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
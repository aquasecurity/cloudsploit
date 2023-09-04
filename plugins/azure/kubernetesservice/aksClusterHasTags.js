var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'AKS Cluster Has Tags',
    category: 'Kubernetes Service',
    domain: 'Containers',
    description: 'Ensures that Azure Kubernetes clusters have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify AKS clusters and add tags.',
    link: 'https://learn.microsoft.com/en-us/azure/aks/use-tags',
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
                helpers.addResult(results, 0, 'No existing Kubernetes clusters found', location);
                return rcb();
            }

            for (let cluster of managedClusters.data) {
                if (!cluster.id) continue;

                if (cluster.tags && Object.entries(cluster.tags).length > 0){
                    helpers.addResult(results, 0, 'AKS cluster has tags', location, cluster.id);
                } else {
                    helpers.addResult(results, 2, 'AKS cluster does not have tags', location, cluster.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
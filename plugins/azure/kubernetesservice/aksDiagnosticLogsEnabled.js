var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'AKS Cluster Diagnostic Logs',
    category: 'Kubernetes Service',
    domain: 'Containers',
    severity: 'Medium',
    description: 'Ensures that Azure Kubernetes clusters have diagnostic logs enabled.',
    more_info: 'Enabling diagnostic logging for AKS clusters helps with performance monitoring, troubleshooting, and security optimization.',
    recommended_action: 'Enable diagnostic logging for all AKS clusters.',
    link: 'https://learn.microsoft.com/en-us/azure/aks/monitor-aks#logs',
    apis: ['managedClusters:list','diagnosticSettings:listByAksClusters'],

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

                var diagnosticSettings = helpers.addSource(cache, source, 
                    ['diagnosticSettings', 'listByAksClusters', location, cluster.id]);
 
                if (!diagnosticSettings || diagnosticSettings.err || !diagnosticSettings.data) {
                    helpers.addResult(results, 3, `Unable to query for Kubernetes cluster diagnostic settings: ${helpers.addError(diagnosticSettings)}`,
                        location, cluster.id);
                    continue;
                }

                var found = diagnosticSettings.data.find(ds => ds.logs && ds.logs.length);

                if (found) {
                    helpers.addResult(results, 0, 'AKS cluster has diagnostic logs enabled', location, cluster.id);
                } else {
                    helpers.addResult(results, 2, 'AKS cluster does not have diagnostic logs enabled', location, cluster.id);
                }
              
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
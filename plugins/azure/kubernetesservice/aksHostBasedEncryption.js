var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'AKS Cluster Host Based Encryption',
    category: 'Kubernetes Service',
    domain: 'Containers',
    severity: 'Low',
    description: 'Ensures that host-based encryption is enabled for all node pools in AKS Cluster.',
    more_info: 'Enabling host-based encryption ensures that data stored on the VM host of your AKS agent node VMs is encrypted at rest and flows encrypted to the Storage service. This capability provides an additional measure of security as the data is encrypted end-to-end.',
    recommended_action: 'Enable host-based encryption for all node pools in your AKS clusters.',
    link: 'https://learn.microsoft.com/en-us/azure/aks/enable-host-encryption',
    apis: ['managedClusters:list'],
    realtime_triggers: ['microsoftcontainerservice:managedclusters:write','microsoftcontainerservice:managedclusters:delete','microsoftcontainerservice:managedclusters:agentpools:write','microsoftcontainerservice:managedclusters:agentpools:delete'],

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

            managedClusters.data.forEach(managedCluster => {
                var agentPoolProfiles = managedCluster.agentPoolProfiles;

                if (!agentPoolProfiles || !agentPoolProfiles.length) {
                    helpers.addResult(results, 0,
                        'No existing node pools found', location, managedCluster.id);
                } else {
                    var unencryptedAtHost = agentPoolProfiles.filter(profile => !profile.enableEncryptionAtHost).map(profile => profile.name);
                   
                    if (unencryptedAtHost.length) {
                        helpers.addResult(results, 2,
                            `AKS Cluster does not have encryption at host enabled for following node pools: ${unencryptedAtHost.join(',')} `, location, managedCluster.id);
                    } else {
                        helpers.addResult(results, 0,
                            'AKS Cluster has encryption at host enabled for all node pools', location, managedCluster.id);
                    }

                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
var async = require('async');
var helpers = require('../../../helpers/azure/');
//var compareVersions = require('compare-versions');

module.exports = {
    title: 'Kubernetes Version For Agent Pools',
    category: 'Kubernetes Service',
    description: 'Ensures the kubernetes version is same across the node pools with the cluster.',
    more_info: 'AKS supports provisioning clusters from several versions of Kubernetes. Node pools should be at per with the cluster kubernetes version.',
    recommended_action: 'Upgrade the version of Kubernetes on all AKS clusters node pool to the same version as the cluster.',
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
                helpers.addResult(results, 0, 'No existing Kubernetes clusters found', location);
                return rcb();
            }

            managedClusters.data.forEach(managedCluster => {
                var kubernetesVersion = managedCluster.kubernetesVersion;
                var agentPoolProfiles = managedCluster.agentPoolProfiles;

                if (!agentPoolProfiles || !agentPoolProfiles.length) {
                    helpers.addResult(results, 3,
                        'Unable to query for Kubernetes cluster node profile' , location, managedCluster.id);
                } else {
                    agentPoolProfiles.forEach(agentPoolProfile =>{
                        if (agentPoolProfile.orchestratorVersion &&
                            helpers.compareVersions(agentPoolProfile.orchestratorVersion,kubernetesVersion) === -1 ) {
                            helpers.addResult(results, 2,
                                `The node pool ${agentPoolProfile.name} does not have the cluster Kubernetes version: ${kubernetesVersion}`, location, managedCluster.id);
                        } else {
                            helpers.addResult(results, 0,
                                `The node pool ${agentPoolProfile.name} has the cluster Kubernetes version`, location, managedCluster.id);
                        }
                    });
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
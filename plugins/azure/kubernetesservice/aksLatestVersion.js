var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Kubernetes Latest Version',
    category: 'Kubernetes Service',
    description: 'Ensures the latest version of Kubernetes is installed on AKS clusters',
    more_info: 'AKS supports provisioning clusters from several versions of Kubernetes. Clusters should be kept up to date to ensure Kubernetes security patches are applied.',
    recommended_action: 'Upgrade the version of Kubernetes on all AKS clusters to the latest available version.',
    link: 'https://docs.microsoft.com/en-us/azure/aks/aad-integration',
    apis: ['managedClusters:list', 'managedClusters:getUpgradeProfile'],

    run: function (cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.managedClusters, function (location, rcb) {

            var managedClusters = helpers.addSource(cache, source,
                ['managedClusters', 'getUpgradeProfile', location]);

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
                var clusterIdArr = managedCluster.id.split('/');
                clusterIdArr.length = clusterIdArr.length - 2;
                var clusterId = clusterIdArr.join('/');
                if (managedCluster.controlPlaneProfile &&
                    managedCluster.controlPlaneProfile.upgrades &&
                    managedCluster.controlPlaneProfile.upgrades.length) {
                    helpers.addResult(results, 2,
                        `The managed cluster does not have the latest Kubernetes version: ${managedCluster.controlPlaneProfile.upgrades[0]}`, location, clusterId);
                } else {
                    helpers.addResult(results, 0,
                        'The managed cluster has the latest Kubernetes version', location, clusterId);
                }
            });

            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
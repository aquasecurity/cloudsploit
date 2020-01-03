var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Automatic Node Upgrades Enabled',
    category: 'Kubernetes',
    description: 'Ensures all Kubernetes cluster nodes have automatic upgrades enabled',
    more_info: 'Enabling automatic upgrades on nodes ensures that each node stays current with the latest version of the master branch, also ensuring that the latest security patches are installed to provide the most secure environment.',
    link: 'https://cloud.google.com/kubernetes-engine/docs/how-to/node-auto-upgrades',
    recommended_action: 'Ensure that automatic node upgrades are enabled on all node pools in Kubernetes clusters',
    apis: ['clusters:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.clusters, function(region, rcb){
            let clusters = helpers.addSource(cache, source,
                ['clusters', 'list', region]);

            if (!clusters) return rcb();

            if (clusters.err || !clusters.data) {
                helpers.addResult(results, 3, 'Unable to query Kubernetes clusters: ' + helpers.addError(clusters), region);
                return rcb();
            }

            if (!clusters.data.length) {
                helpers.addResult(results, 0, 'No Kubernetes clusters found', region);
                return rcb();
            }

            clusters.data.forEach(cluster => {
                if (cluster.nodePools &&
                    cluster.nodePools.length) {
                    cluster.nodePools.forEach(nodePool => {
                        if (nodePool.management &&
                            nodePool.management.autoUpgrade) {
                            helpers.addResult(results, 0,
                                `Auto upgrades are enabled for the node pool of the cluster: ${cluster.name}`, region, nodePool.name);
                        } else {
                            helpers.addResult(results, 2,
                                `Auto upgrades are disabled for the node pool of the cluster: ${cluster.name}`, region, nodePool.name);
                        }
                    })
                } else {
                    helpers.addResult(results, 0, 'No node pools found', region, cluster.name);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
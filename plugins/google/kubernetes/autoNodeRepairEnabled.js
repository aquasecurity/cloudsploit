var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Automatic Node Repair Enabled',
    category: 'Kubernetes',
    description: 'Ensures all Kubernetes cluster nodes have automatic repair enabled',
    more_info: 'When automatic repair on nodes is enabled, the Kubernetes engine performs health checks on all nodes, automatically repairing nodes that fail health checks. This ensures that the Kubernetes environment stays optimal.',
    link: 'https://cloud.google.com/kubernetes-engine/docs/how-to/node-auto-repair',
    recommended_action: 'Ensure that automatic node repair is enabled on all node pools in Kubernetes clusters',
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
                            nodePool.management.autoRepair) {
                            helpers.addResult(results, 0,
                                `Auto repair is enabled for the node pool of the cluster: ${cluster.name}`, region, nodePool.name);
                        } else {
                            helpers.addResult(results, 2,
                                `Auto repair is disabled for the node pool of the cluster: ${cluster.name}`, region, nodePool.name);
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
var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Default Service Account',
    category: 'Kubernetes',
    description: 'Ensures all Kubernetes cluster nodes are not using the default service account.',
    more_info: 'Kubernetes cluster nodes should use customized service accounts that have minimal privileges to run. This reduces the attack surface in the case of a malicious attack on the cluster.',
    link: 'https://cloud.google.com/container-optimized-os/',
    recommended_action: 'Ensure that no Kubernetes cluster nodes are using the default service account',
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
                        if (nodePool.config &&
                            nodePool.config.serviceAccount &&
                            nodePool.config.serviceAccount === "default") {
                            helpers.addResult(results, 2,
                                `The default service account is being used for the node pool of the cluster: ${cluster.name}`, region, nodePool.name);
                        } else {
                            helpers.addResult(results, 0,
                                `The default service account is not being used for the node pool of the cluster: ${cluster.name}`, region, nodePool.name);
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
};
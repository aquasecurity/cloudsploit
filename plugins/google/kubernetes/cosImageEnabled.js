var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'COS Image Enabled',
    category: 'Kubernetes',
    description: 'Ensures all Kubernetes cluster nodes have Container-Optimized OS enabled',
    more_info: 'Container-Optimized OS is optimized to enhance node security. It is backed by a team at Google that can quickly patch it.',
    link: 'https://cloud.google.com/container-optimized-os/',
    recommended_action: 'Enable Container-Optimized OS on all Kubernetes cluster nodes',
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
                            nodePool.config.imageType &&
                            nodePool.config.imageType === "COS") {
                            helpers.addResult(results, 0,
                                `Container-Optimized OS is enabled for the node pool of the cluster: ${cluster.name}`, region, nodePool.name);
                        } else {
                            helpers.addResult(results, 2,
                                `Container-Optimized OS disabled for the node pool of the cluster: ${cluster.name}`, region, nodePool.name);
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
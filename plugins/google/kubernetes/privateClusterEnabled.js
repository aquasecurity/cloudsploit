var async   = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Private Cluster Enabled',
    category: 'Kubernetes',
    description: 'Ensures private cluster is enabled for all Kubernetes clusters',
    more_info: 'Kubernetes private clusters only have internal ip ranges, which ensures that their workloads are isolated from the public internet.',
    link: 'https://cloud.google.com/kubernetes-engine/docs/how-to/private-clusters',
    recommended_action: 'Ensure that all Kubernetes clusters have private cluster enabled.',
    apis: ['clusters:list'],

    run: function(cache, settings, callback) {

        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.clusters, (region, rcb) => {
            var clusters = helpers.addSource(cache, source,
                ['clusters', 'list', region]);

            if (!clusters) return rcb();

            if (clusters.err || !clusters.data) {
                helpers.addResult(results, 3,
                    'Unable to query for clusters: ' + helpers.addError(clusters), region);
                return rcb();
            }

            if (!clusters.data.length) {
                helpers.addResult(results, 0, 'No clusters found', region);
                return rcb();
            }

            clusters.data.forEach(cluster => {
                if (cluster.privateCluster) {
                    helpers.addResult(results, 0, 'Private cluster is enabled on the Kubernetes cluster', region, cluster.name);
                } else {
                    helpers.addResult(results, 2, 'Private cluster is disabled on the Kubernetes cluster', region, cluster.name);
                }

            });
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
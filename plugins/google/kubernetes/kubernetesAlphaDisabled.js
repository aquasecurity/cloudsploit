var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Kubernetes Alpha Disabled',
    category: 'Kubernetes',
    description: 'Ensure the GKE Cluster alpha cluster feature is disabled.',
    more_info: 'It is recommended to not use Alpha clusters as they expire after thirty days and do not receive security updates.',
    link: 'https://cloud.google.com/kubernetes-engine/docs/concepts/alpha-clusters',
    recommended_action: '1. Create a new cluster with the alpha feature disabled. 2. Migrate all required cluster data from the cluster with alpha to this newly created cluster. 3.Delete the engine cluster with alpha enabled.',
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
                helpers.addResult(results, 3, 'Unable to query Kubernetes clusters', region, null, null, clusters.err);
                return rcb();
            }

            if (!clusters.data.length) {
                helpers.addResult(results, 0, 'No Kubernetes clusters found', region);
                return rcb();
            }

            clusters.data.forEach(cluster => {
                if (!cluster.name) return;

                if (!cluster.enableKubernetesAlpha) {
                    helpers.addResult(results, 0,
                        'Kubernetes cluster has alpha feature disabled', region, cluster.name);
                } else {
                    helpers.addResult(results, 2,
                        'Kubernetes cluster does not have alpha feature disabled', region, cluster.name);
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Monitoring Enabled',
    category: 'Kubernetes',
    description: 'Ensures all Kubernetes clusters have logging enabled.',
    more_info: 'This setting should be enabled to ensure Kubernetes control plane logs are properly recorded',
    link: 'https://cloud.google.com/monitoring/kubernetes-engine/legacy-stackdriver/logging',
    recommended_action: 'Ensure that logging is enabled on all Kubernetes clusters',
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
                helpers.addResult(results, 3,
                    'Unable to query Kubernetes clusters: ' + helpers.addError(clusters), region);
                return rcb();
            }

            if (!clusters.data.length) {
                helpers.addResult(results, 0, 'No Kubernetes clusters present', region);
                return rcb();
            }

            var badClusters = false;
            clusters.data.forEach(cluster => {
                if (!cluster.loggingService ||
                    (cluster.loggingService &&
                    cluster.loggingService === 'none')) {
                    badClusters = true;
                    helpers.addResult(results, 2,
                        `Logging is disabled on the Kubernetes cluster: ${cluster.name}`, region);
                }
            });

            if (!badClusters) {
                helpers.addResult(results, 0, 'Logging is enabled on all clusters', region);
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Monitoring Enabled',
    category: 'Kubernetes',
    description: 'Ensures all Kubernetes clusters have monitoring enabled',
    more_info: 'Kubernetes supports monitoring through Stackdriver.',
    link: 'https://cloud.google.com/monitoring/kubernetes-engine/',
    recommended_action: 'Ensure monitoring is enabled on all Kubernetes clusters.',
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
            var badClusters = false;
            clusters.data.forEach(cluster => {
                if (cluster.monitoringService &&
                    cluster.monitoringService == 'none') {
                    badClusters = true;
                    helpers.addResult(results, 2, 'Monitoring is disabled on the Kubernetes cluster', region, cluster.name);
                } else {
                    helpers.addResult(results, 0, 'Monitoring is enabled on the Kubernetes cluster', region, cluster.name);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
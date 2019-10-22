var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Monitoring Enabled',
    category: 'Kubernetes',
    description: 'Ensures all Kubernetes clusters have monitoring enabled ',
    more_info: 'Kubernetes supports monitoring through Stackdriver.',
    link: 'https://cloud.google.com/monitoring/kubernetes-engine/',
    recommended_action: '1. Enter the Kubernetes Service. 2. Select Clusters from the left blade. 3. Select edit on the cluster. 4. Enable Stackdriver Kubernetes Engine Monitoring or Legacy Stackdriver Monitoring.',
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
                helpers.addResult(results, 3, 'Unable to query Kubernetes Clusters: ' + helpers.addError(clusters), region);
                return rcb();
            };

            if (!clusters.data.length) {
                helpers.addResult(results, 0, 'No Kubernetes Clusters present', region);
                return rcb();
            };
            var badClusters = false;
            clusters.data.forEach(cluster => {
                if (cluster.monitoringService &&
                    cluster.monitoringService == 'none') {
                    badClusters = true;
                    helpers.addResult(results, 2, `No Monitoring is enabled on the kubernetes cluster: ${cluster.name}`, region);
                };
            });

            if (!badClusters) {
                helpers.addResult(results, 0, 'Monitoring is enabled on all clusters', region);
            };

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
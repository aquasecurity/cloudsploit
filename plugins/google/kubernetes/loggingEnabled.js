var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Logging Enabled',
    category: 'Kubernetes',
    description: 'Ensures all Kubernetes clusters have logging enabled',
    more_info: 'This setting should be enabled to ensure Kubernetes control plane logs are properly recorded.',
    link: 'https://cloud.google.com/monitoring/kubernetes-engine/legacy-stackdriver/logging',
    recommended_action: 'Ensure that logging is enabled on all Kubernetes clusters.',
    apis: ['clusters:list'],
    compliance: {
        hipaa: 'HIPAA requires the logging of all activity ' +
            'including access and all actions taken.'
    },

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
                helpers.addResult(results, 0, 'No Kubernetes clusters found', region);
                return rcb();
            }

            clusters.data.forEach(cluster => {
                if (!cluster.loggingService ||
                    (cluster.loggingService &&
                    cluster.loggingService === 'none')) {
                    helpers.addResult(results, 2,
                        'Logging is disabled on the Kubernetes cluster', region, cluster.name);
                } else {
                    helpers.addResult(results, 0, 'Logging is enabled on the cluster', region, cluster.name);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
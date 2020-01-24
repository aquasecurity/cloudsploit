var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Web Dashboard Disabled',
    category: 'Kubernetes',
    description: 'Ensures all Kubernetes clusters have the web dashboard disabled.',
    more_info: 'It is recommended to disable the web dashboard because it is backed by a highly privileged service account.',
    link: 'https://cloud.google.com/kubernetes-engine/docs/concepts/dashboards',
    recommended_action: 'Ensure that no Kubernetes clusters have the web dashboard enabled',
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
                if (cluster.addonsConfig &&
                    cluster.addonsConfig.kubernetesDashboard &&
                    cluster.addonsConfig.kubernetesDashboard.disabled) {
                    helpers.addResult(results, 0,
                        'The web dashboard is disabled for the Kubernetes cluster', region, cluster.name);
                } else {
                    helpers.addResult(results, 2,
                        'The web dashboard is enabled for the Kubernetes cluster', region, cluster.name);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
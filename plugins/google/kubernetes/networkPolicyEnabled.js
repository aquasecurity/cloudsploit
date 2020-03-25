var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Network Policy Enabled',
    category: 'Kubernetes',
    description: 'Ensures all Kubernetes clusters have network policy enabled',
    more_info: 'Kubernetes network policy creates isolation between cluster pods, this creates a more secure environment with only specified connections allowed.',
    link: 'https://cloud.google.com/kubernetes-engine/docs/how-to/network-policy',
    recommended_action: 'Enable network policy on all Kubernetes clusters.',
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
                helpers.addResult(results, 0, 'No clusters found', region);
                return rcb();
            }

            clusters.data.forEach(cluster => {
                if (cluster.networkPolicy &&
                    cluster.networkPolicy.enabled) {
                    helpers.addResult(results, 0, 'Network policy is enabled for the Kubernetes cluster', region, cluster.name);
                } else {
                    helpers.addResult(results, 2, 'Network policy is disabled for the Kubernetes cluster', region, cluster.name);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
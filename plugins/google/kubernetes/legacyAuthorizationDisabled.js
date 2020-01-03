var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Legacy Authorization Disabled',
    category: 'Kubernetes',
    description: 'Ensure legacy authorization is set to disabled on Kubernetes clusters',
    more_info: 'The legacy authorizer in Kubernetes grants broad, statically defined permissions.',
    link: 'https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster',
    recommended_action: 'Disable legacy authorization on all clusters.',
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
                if (cluster.legacyAbac &&
                    cluster.legacyAbac.enabled) {
                    helpers.addResult(results, 2, 'Legacy Authorization is enabled on the cluster', region, cluster.name);
                } else {
                    helpers.addResult(results, 0, 'Legacy Authorization is disabled on the cluster', region, cluster.name);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Alias IP Ranges Enabled',
    category: 'Kubernetes',
    description: 'Ensures all Kubernetes clusters have alias IP ranges enabled',
    more_info: 'Alias IP ranges allow users to assign ranges of internal IP addresses as alias to a network interface.',
    link: 'https://cloud.google.com/monitoring/kubernetes-engine/',
    recommended_action: 'Ensure that Kubernetes clusters have alias IP ranges enabled.',
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
                if (cluster.ipAllocationPolicy &&
                    cluster.ipAllocationPolicy.useIpAliases) {
                    helpers.addResult(results, 0, 'Kubernetes alias IP ranges enabled', region, cluster.name);
                } else {
                    helpers.addResult(results, 2, 'Kubernetes alias IP ranges disabled', region, cluster.name);

                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
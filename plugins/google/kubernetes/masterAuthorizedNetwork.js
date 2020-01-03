var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Master Authorized Network',
    category: 'Kubernetes',
    description: 'Ensures master authorized networks is set to enabled on Kubernetes clusters',
    more_info: 'Authorized networks are a way of specifying a restricted range of IP addresses that are permitted to access your container clusters Kubernetes master endpoint.',
    link: 'https://cloud.google.com/kubernetes-engine/docs/how-to/authorized-networks',
    recommended_action: 'Enable master authorized networks on all clusters.',
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
                if (cluster.masterAuthorizedNetworksConfig &&
                    cluster.masterAuthorizedNetworksConfig.enabled) {
                    helpers.addResult(results, 0, 'Master Authorized Network is enabled on the Kubernetes cluster', region, cluster.name);
                } else {
                    helpers.addResult(results, 2, 'Master Authorized Network is disabled on the Kubernetes cluster', region, cluster.name);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
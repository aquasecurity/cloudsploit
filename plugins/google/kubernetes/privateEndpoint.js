var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Private Endpoint',
    category: 'Kubernetes',
    description: 'Ensures the private endpoint setting is enabled for kubernetes clusters',
    more_info: 'kubernetes private endpoints can be used to route all traffic between the Kubernetes worker and control plane nodes over a private VPC endpoint rather than across the public internet.',
    link: 'https://cloud.google.com/kubernetes-engine/docs/how-to/private-clusters',
    recommended_action: 'Enable the private endpoint setting for all GKE clusters when creating the cluster.',
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
            };

            if (!clusters.data.length) {
                helpers.addResult(results, 0, 'No Kubernetes clusters found', region);
                return rcb();
            };
            clusters.data.forEach(cluster => {
                if (cluster.privateClusterConfig &&
                    cluster.privateClusterConfig.privateEndpoint) {
                    helpers.addResult(results, 0, 'Kubernetes cluster has private endpoint enabled', region, cluster.name);
                } else {
                    helpers.addResult(results, 2, 'Kubernetes cluster does not have private endpoint enabled', region, cluster.name);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}

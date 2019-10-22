var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Private Endpoint',
    category: 'Kubernetes',
    description: 'Ensures the private endpoint setting is enabled for kubernetes clusters',
    more_info: 'kubernetes private endpoints can be used to route all traffic between the Kubernetes worker and control plane nodes over a private VPC endpoint rather than across the public internet.',
    link: 'https://cloud.google.com/kubernetes-engine/docs/how-to/private-clusters',
    recommended_action: 'Enable the private endpoint setting for all EKS clusters when creating the cluster.',
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
            clusters.data.forEach(cluster => {
                if (cluster.privateClusterConfig &&
                    cluster.privateClusterConfig.privateEndpoint) {
                    helpers.addResult(results, 0, `kubernetes cluster: ${cluster.name} has private endpoint enabled`, region);
                } else {
                    helpers.addResult(results, 2, `kubernetes cluster: ${cluster.name} does not have private endpoint enabled`, region);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
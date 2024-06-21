var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'OKE Private Endpoint',
    category: 'OKE',
    domain: 'Containers',
    severity: 'Medium',
    description: 'Ensures the private endpoint setting is enabled for OKE clusters.',
    more_info: 'OKE private endpoints can be used to route all traffic between the Kubernetes worker and control plane nodes over a private VCN endpoint rather than across the public internet.',
    recommended_action: 'Enable the private endpoint setting for all OKE clusters.',
    link: 'https://docs.oracle.com/en-us/iaas/Content/ContEng/Concepts/contengclustersnodes.htm#processes',
    apis: ['cluster:list'],
   
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.cluster, function(region, rcb){

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var clusters = helpers.addSource(cache, source,
                    ['cluster', 'list', region]);

                if (!clusters) return rcb();

                if (clusters.err || !clusters.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for OKE clusters: ' + helpers.addError(clusters), region);
                    return rcb();
                }

                if (!clusters.data.length) {
                    helpers.addResult(results, 0, 'No OKE clusters found', region);
                    return rcb();
                }

                clusters.data.forEach(cluster => {
                    if (cluster.lifecycleState && cluster.lifecycleState === 'DELETED') return;
        
                    if (cluster.endpointConfig && cluster.endpointConfig.isPublicIpEnabled) {
                        helpers.addResult(results, 2, 'OKE cluster does not have private endpoint enabled', region, cluster.id);
                    } else {
                        helpers.addResult(results, 0, 'OKE cluster has private endpoint enabled', region, cluster.id);
                    }
                });
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};


       
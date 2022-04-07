var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'MSK Cluster Unauthenticated Access',
    category: 'MSK',
    domain: 'Compute',
    severity: 'Medium',
    description: 'Ensure that Unauthentication is disabled within the cluster feature for your Amazon MSK clusters.',
    more_info: 'Amazon MSK authenticate clients to allow or deny Apache Kafka actions. Alternatively, TLS or SASL/SCRAM can be used to authenticate clients, and Apache Kafka ACLs to allow or deny actions.',
    link: 'https://docs.aws.amazon.com/msk/latest/developerguide/msk-authentication.html',
    recommended_action: 'Check for Unauthentication disabled within the cluster for all MSK clusters to allow or deny actions for clients',
    apis: ['Kafka:listClusters'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.kafka, function(region, rcb){
            var listClusters = helpers.addSource(cache, source,
                ['kafka', 'listClusters', region]);

            if (!listClusters) return rcb();

            if (listClusters.err || !listClusters.data) {
                helpers.addResult(results, 3,
                    'Unable to query for MSK clusters: ' + helpers.addError(listClusters), region);
                return rcb();
            }

            if (!listClusters.data.length) {
                helpers.addResult(results, 0, 'No MSK clusters found', region);
                return rcb();
            }
            
            for (var cluster of listClusters.data) {
                if (!cluster.ClusterArn) continue;

                var resource = cluster.ClusterArn;

                if (cluster.ClientAuthentication && 
                    cluster.ClientAuthentication.Unauthenticated && 
                    cluster.ClientAuthentication.Unauthenticated.Enabled == true) {
                    helpers.addResult(results, 2,
                        'Unauthentication is enabled for clients, and all actions are allowed', region, resource);
                } else {
                    helpers.addResult(results, 0,
                        'Unauthentication is disabled for clients, and all actions are not allowed', region, resource);
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};

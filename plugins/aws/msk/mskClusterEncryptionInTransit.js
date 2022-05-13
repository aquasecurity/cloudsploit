var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'MSK Cluster Encryption In-Transit',
    category: 'MSK',
    domain: 'Compute',
    severity: 'Medium',
    description: 'Ensure that TLS encryption within the cluster feature is enabled for your Amazon MSK clusters.',
    more_info: 'Amazon MSK in-transit encryption is an optional feature which encrypts data in transit within your MSK cluster. You can override this default at the time you create the cluster.',
    link: 'https://docs.aws.amazon.com/msk/latest/developerguide/msk-encryption.html',
    recommended_action: 'Enable TLS encryption within the cluster for all MSK clusters',
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

                if (cluster.EncryptionInfo && 
                    cluster.EncryptionInfo.EncryptionInTransit && 
                    cluster.EncryptionInfo.EncryptionInTransit.InCluster) {
                    helpers.addResult(results, 0,
                        'TLS encryption within the cluster is enabled', region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'TLS encryption within the cluster is not enabled', region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};

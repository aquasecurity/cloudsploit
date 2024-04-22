var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'MSK Cluster Client Broker Encryption',
    category: 'MSK',
    domain: 'Compute',
    severity: 'Low',
    description: 'Ensure that only TLS encryption between the client and broker feature is enabled for your Amazon MSK clusters.',
    more_info: 'Amazon MSK in-transit encryption is an optional feature which encrypts data in transit between the client and brokers. Select the Transport Layer Security (TLS) protocol to encrypt data as it travels between brokers and clients within the cluster.',
    link: 'https://docs.aws.amazon.com/msk/latest/developerguide/msk-encryption.html',
    recommended_action: 'Enable only TLS encryption between the client and broker for all MSK clusters',
    apis: ['Kafka:listClusters'],
    realtime_triggers: ['kafka:CreateCluster','kafka:UpdateClusterConfiguration', 'kafka:DeleteCluster'],

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
                    cluster.EncryptionInfo.EncryptionInTransit.ClientBroker &&
                    cluster.EncryptionInfo.EncryptionInTransit.ClientBroker.toUpperCase() === 'TLS') {
                    helpers.addResult(results, 0,
                        'Encryption between the client and broker is only TLS encrypted', region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Encryption between the client and broker is not only TLS encrypted', region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};

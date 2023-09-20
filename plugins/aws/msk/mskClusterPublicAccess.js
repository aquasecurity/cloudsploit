var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'MSK Cluster Public Access',
    category: 'MSK',
    domain: 'Compute',
    severity: 'Medium',
    description: 'Ensure that public access feature within the cluster is disabled for your Amazon MSK clusters.',
    more_info: 'Amazon MSK gives you the option to turn on public access to the brokers of MSK clusters running Apache Kafka 2.6.0 or later versions. For security reasons, you cannot turn on public access while creating an MSK cluster. However, you can update an existing cluster to make it publicly accessible.',
    link: 'https://docs.aws.amazon.com/msk/latest/developerguide/public-access.html',
    recommended_action: 'Check for public access feature within the cluster for all MSK clusters',
    apis: ['Kafka:listClusters'],
    realtime_triggers: ['kafka:CreateCluster', 'kafka:DeleteCluster'],

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

                if (cluster.BrokerNodeGroupInfo &&
                    cluster.BrokerNodeGroupInfo.ConnectivityInfo && 
                    cluster.BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess && 
                    cluster.BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess.Type &&
                    cluster.BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess.Type.toUpperCase() === 'DISABLED') {
                    helpers.addResult(results, 0,
                        'MSK cluster is not publicly accessible', region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'MSK cluster is publicly accessible', region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};

var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Redshift Desired Node Type',
    category: 'Redshift',
    description: 'Ensures that Amazon Redshift cluster nodes are of given types.',
    more_info: 'Amazon Redshift clusters nodes should be of the given types to ensure the internal compliance and prevent unexpected billing charges.',
    link: 'https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-clusters.html#working-with-clusters-overview',
    recommended_action: 'Take snapshot of the Amazon Redshift cluster and launch a new cluster of the desired node type using the snapshot.',
    apis: ['Redshift:describeClusters', 'STS:getCallerIdentity'],
    settings: {
        redshift_cluster_node_type: {
            name: 'Redshift Cluster Node Type',
            description: 'Desired Amazon Redshift cluster node type',
            regex: '^.*$',
            default: ''
        },
    },

    run: function(cache, settings, callback) {
        var redshift_cluster_node_type = settings.redshift_cluster_node_type || this.settings.redshift_cluster_node_type.default;

        if (!redshift_cluster_node_type.length) return callback();

        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);


        async.each(regions.redshift, function(region, rcb){
            var describeClusters = helpers.addSource(cache, source,
                ['redshift', 'describeClusters', region]);

            if (!describeClusters) return rcb();

            if (describeClusters.err || !describeClusters.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Redshift clusters: ' + helpers.addError(describeClusters), region);
                return rcb();
            }

            if (!describeClusters.data.length) {
                helpers.addResult(results, 0, 'No Redshift clusters found', region);
                return rcb();
            }

            describeClusters.data.forEach(cluster => {
                if (!cluster.ClusterIdentifier) return;

                var clusterIdentifier = cluster.ClusterIdentifier;
                var resource = `arn:${awsOrGov}:redshift:${region}:${accountId}:cluster:${clusterIdentifier}`;

                if (cluster.NodeType && cluster.NodeType === redshift_cluster_node_type) {
                    helpers.addResult(results, 0,
                        'Redshift cluster is using the desired node type', region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Redshift cluster is not using the desired node type', region, resource);
                }
            });
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};

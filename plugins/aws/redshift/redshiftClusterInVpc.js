var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Redshift Cluster In VPC',
    category: 'Redshift',
    domain: 'Databases',
    description: 'Ensures that Amazon Redshift clusters are launched within a Virtual Private Cloud (VPC).',
    more_info: 'Amazon Redshift clusters should be launched within a Virtual Private Cloud (VPC) to ensure cluster security.',
    link: 'https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-clusters.html#cluster-platforms',
    recommended_action: 'Update Amazon Redshift cluster and attach it to VPC',
    apis: ['Redshift:describeClusters', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
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
                    `Unable to query for Redshift clusters: ${helpers.addError(describeClusters)}`, region);
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

                if (cluster.VpcId && cluster.VpcId.length) {
                    helpers.addResult(results, 0,
                        'Redshift cluster is launched within a VPC', region, resource);    
                } else {
                    helpers.addResult(results, 2,
                        'Redshift cluster is not launched within a VPC', region, resource);
                }
            });
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};

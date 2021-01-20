var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Redshift Cluster Default Port',
    category: 'Redshift',
    description: 'Ensures that Amazon Redshift clusters are not using port "5439" (default port) for database access.',
    more_info: 'Amazon Redshift clusters should not use the default port for database access to ensure cluster security.',
    link: 'https://docs.amazonaws.cn/en_us/redshift/latest/gsg/rs-gsg-launch-sample-cluster.html',
    recommended_action: 'Update Amazon Redshift cluster endpoint port.',
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

                if (cluster.Endpoint && cluster.Endpoint.Port && cluster.Endpoint.Port === 5439) {
                    helpers.addResult(results, 2,
                        'Redshift cluster is using default "5439" port', region, resource);
                } else {
                    helpers.addResult(results, 0,
                        'Redshift cluster is not using default "5439" port', region, resource);
                }
            });
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};

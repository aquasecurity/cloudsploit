var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElastiCache Redis Cluster Have Multi-AZ',
    category: 'ElastiCache',
    domain: 'Databases',
    description: 'Ensure that your ElastiCache Redis Cache clusters are using a Multi-AZ deployment configuration to enhance High Availability.',
    more_info: 'Enabling the Multi-AZ feature for your Redis Cache clusters will improve the fault tolerance in case the read/write primary node becomes unreachable due to loss of network connectivity, loss of availability in the primary’s AZ, etc. ',
    link: 'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/AutoFailover.html#AutoFailover.Enable',
    recommended_action: 'Enable Redis Multi-AZ for ElastiCache clusters',
    apis: ['ElastiCache:describeCacheClusters', 'ElastiCache:describeReplicationGroups'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.elasticache, function(region, rcb) {
            var describeCacheClusters = helpers.addSource(cache, source,
                ['elasticache', 'describeCacheClusters', region]);

            if (!describeCacheClusters) return rcb();

            if (describeCacheClusters.err || !describeCacheClusters.data) {
                helpers.addResult(results, 3,
                    'Unable to query elasticache clusters: ' + helpers.addError(describeCacheClusters), region);
                return rcb();
            }

            if (!describeCacheClusters.data.length) {
                helpers.addResult(results, 0, 'No elasticache clusters found', region);
                return rcb();
            }

            for (let cluster of describeCacheClusters.data) {
                if (!cluster.ARN) continue;

                var resource = cluster.ARN;
                var describeReplicationGroups = helpers.addSource(cache, source,
                    ['elasticache', 'describeReplicationGroups', region, cluster.ReplicationGroupId]);

                if (!describeReplicationGroups || describeReplicationGroups.err || !describeReplicationGroups.data) {
                    helpers.addResult(results, 3,
                        `Unable to get clusters description: ${helpers.addError(describeReplicationGroups)}`,
                        region, resource);
                } else {
                    if (describeReplicationGroups.data.MultiAZ === 'enabled') {
                        helpers.addResult(results, 0,
                            'Cluster has Multi-AZ feature enabled', region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'Cluster does not have Multi-AZ feature enabled', region, resource);
                    }
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
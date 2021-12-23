var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Unused ElastiCache Reserved Cache Nodes',
    category: 'ElastiCache',
    domain: 'Databases',
    description: 'Ensure that all your AWS ElastiCache reserved nodes have corresponding cache nodes running within the same account of an AWS Organization.',
    more_info: 'Creating cache nodes for your unused reserved cache clusters will prevent your investment having a negative return. When an Amazon ElastiCache RCN is not in use the investment made is not properly exploited.',
    link: 'https://aws.amazon.com/elasticache/reserved-cache-nodes/',
    recommended_action: 'Enable prevention of unused reserved nodes for ElastiCache clusters',
    apis: ['ElastiCache:describeCacheClusters', 'ElastiCache:describeReservedCacheNodes'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.elasticache, function(region, rcb){
            var describeCacheClusters = helpers.addSource(cache, source,
                ['elasticache', 'describeCacheClusters', region]);

            var describeReservedCacheNodes = helpers.addSource(cache, source,
                ['elasticache', 'describeReservedCacheNodes', region]);
    
            if (!describeReservedCacheNodes) return rcb();

            if (describeReservedCacheNodes.err || !describeReservedCacheNodes.data) {
                helpers.addResult(results, 3,
                    'Unable to query for elasticache reserved nodes: ' + helpers.addError(describeReservedCacheNodes), region);
                return rcb();
            }

            if (!describeReservedCacheNodes.data.length) {
                helpers.addResult(results, 0, 'No elasticache reserved nodes found', region);
                return rcb();
            }

            if (!describeCacheClusters || describeCacheClusters.err || !describeCacheClusters.data) {
                helpers.addResult(results, 3,
                    'Unable to query for elasticache clusters: ' + helpers.addError(describeCacheClusters), region);
                return rcb();
            }

            var usedReservedNodes = [];
            describeCacheClusters.data.forEach(cluster => {
                if (!cluster.CacheClusterId) return;

                if (!usedReservedNodes.includes(cluster.CacheNodeType)) {
                    usedReservedNodes.push(cluster.CacheNodeType);
                }
            });

            describeReservedCacheNodes.data.forEach(node => {
                if (usedReservedNodes.includes(node.CacheNodeType)) {
                    helpers.addResult(results, 0,
                        `ElastiCache reserved cache node "${node.ReservedCacheNodeId}" is being used`,
                        region, node.ReservationARN);
                } else {
                    helpers.addResult(results, 2,
                        `ElastiCache reserved cache node "${node.ReservedCacheNodeId}" is not being used`,
                        region, node.ReservationARN);
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};

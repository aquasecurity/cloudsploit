var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElastiCache Nodes Count',
    category: 'ElastiCache',
    domain: 'Databases',
    description: 'Ensure that the number of ElastiCache cluster cache nodes provisioned in your AWS account has not reached the limit quota established by your organization for the ElastiCache workload deployed',
    more_info: 'Monitoring and setting limits for the maximum number of ElastiCache cluster nodes provisioned within your AWS account will help you to better manage your ElastiCache compute resources and prevent unexpected charges on your AWS bill',
    link: 'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/CacheNodes.html',
    recommended_action: 'Enable limit for ElastiCache cluster nodes count',
    apis: ['ElastiCache:describeCacheClusters'],
    settings: {
        elasticache_nodes_count: {
            name: 'Amazon ElastiCache Nodes Count',
            description: 'Maximum Amazon ElastiCache nodes count per region',
            regex: '^[0-9]{1,4}',
            default: '100'
        },
    },

    run: function(cache, settings, callback) {
        var elasticache_nodes_count = parseInt(settings.elasticache_nodes_count || this.settings.elasticache_nodes_count.default);

        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.elasticache, function(region, rcb){
            var describeCacheClusters = helpers.addSource(cache, source,
                ['elasticache', 'describeCacheClusters', region]);

            if (!describeCacheClusters) return rcb();

            if (describeCacheClusters.err || !describeCacheClusters.data) {
                helpers.addResult(results, 3,
                    'Unable to query for ElastiCache clusters: ' + helpers.addError(describeCacheClusters), region);
                return rcb();
            }

            if (!describeCacheClusters.data.length) {
                helpers.addResult(results, 0, 'No ElastiCache clusters found', region);
                return rcb();
            }

            var nodesCount = 0;
            describeCacheClusters.data.forEach(cluster => {
                if (!cluster.CacheClusterId) return;

                if (cluster.NumCacheNodes) {
                    nodesCount = nodesCount + cluster.NumCacheNodes;
                }
            });

            if (nodesCount <= elasticache_nodes_count) {
                helpers.addResult(results, 0,
                    `Region contains "${nodesCount}" provisioned ElastiCache nodes of "${elasticache_nodes_count}" limit`, region);
            } else {
                helpers.addResult(results, 2,
                    `Region contains "${nodesCount}" provisioned ElastiCache nodes of "${elasticache_nodes_count}" limit`, region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};

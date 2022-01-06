var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElastiCache Nodes Count',
    category: 'ElastiCache',
    domain: 'Databases',
    description: 'Ensure that the number of ElastiCache cluster cache nodes has not reached the limit quota established by your organization.',
    more_info: 'Defining limits for the maximum number of ElastiCache cluster nodes that can be created within your AWS account will help you to better manage your ElastiCache compute resources and prevent unexpected charges on your AWS bill.',
    link: 'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/CacheNodes.html',
    recommended_action: 'Enable limit for ElastiCache cluster nodes count',
    apis: ['ElastiCache:describeCacheClusters'],
    settings: {
        elasticache_nodes_count_per_region: {
            name: 'Amazon ElastiCache Nodes Count Per Region',
            description: 'Maximum Amazon ElastiCache nodes count per region',
            regex: '^[0-9]{1,4}',
            default: '100'
        },
        elasticache_nodes_count_global: {
            name: 'Amazon ElastiCache Nodes Count Global',
            description: 'Maximum Amazon ElastiCache nodes count per region',
            regex: '^[0-9]{1,4}',
            default: '200'
        },
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        
        var config = {
            elasticache_nodes_count_per_region: parseInt(settings.elasticache_nodes_count_per_region || this.settings.elasticache_nodes_count_per_region.default),
            elasticache_nodes_count_global: parseInt(settings.elasticache_nodes_count_global || this.settings.elasticache_nodes_count_global.default)
        };

        var globalCount = 0;
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
                    globalCount = globalCount + cluster.NumCacheNodes;
                }
            });

            if (nodesCount <= config.elasticache_nodes_count_per_region) {
                helpers.addResult(results, 0,
                    `Region contains "${nodesCount}" provisioned ElastiCache nodes of "${config.elasticache_nodes_count_per_region}" limit`, region);
            } else {
                helpers.addResult(results, 2,
                    `Region contains "${nodesCount}" provisioned ElastiCache nodes of "${config.elasticache_nodes_count_per_region}" limit`, region);
            }

            rcb();
        }, function(){
            if (globalCount <= config.elasticache_nodes_count_global) {
                helpers.addResult(results, 0,
                    `Region contains "${globalCount}" provisioned ElastiCache nodes of "${config.elasticache_nodes_count_global}" limit`, 'global');
            } else {
                helpers.addResult(results, 2,
                    `Region contains "${globalCount}" provisioned ElastiCache nodes of "${config.elasticache_nodes_count_global}" limit`, 'global');
            }

            callback(null, results, source);
        });
    }
};

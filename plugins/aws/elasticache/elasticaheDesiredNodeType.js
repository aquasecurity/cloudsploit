var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElastiCache Desired Node Type',
    category: 'ElastiCache',
    domain: 'Databases',
    description: 'Ensure that the Amazon ElastiCache cluster nodes provisioned in your AWS account have the desired node type established within your organization based on the workload deployed.',
    more_info: 'Setting limits for the type of Amazon ElastiCache cluster nodes will help you address internal compliance requirements and prevent unexpected charges on your AWS bill.',
    recommended_action: 'Create ElastiCache clusters with desired node types',
    link: 'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/WhatIs.html',
    apis: ['ElastiCache:describeCacheClusters'],
    settings: {
        elasticache_desired_node_type: {
            name: 'ElastiCache Cluster Desired Node Type',
            description: 'ElastiCache Cluster should be using the desired node type',
            regex: '^.*$',
            default:'cache.t2.micro'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            elasticache_desired_node_type: settings.elasticache_desired_node_type || this.settings.elasticache_desired_node_type.default
        };
        
        if (!config.elasticache_desired_node_type.length) return callback(null, results, source);
      
        async.each(regions.elasticache, function(region, rcb){        
            var describeCacheClusters = helpers.addSource(cache, source,
                ['elasticache', 'describeCacheClusters', region]);
                
            if (!describeCacheClusters) return rcb();

            if (describeCacheClusters.err || !describeCacheClusters.data) {
                helpers.addResult(results, 3,
                    'Unable to query ElastiCache cluster: ' + helpers.addError(describeCacheClusters), region);
                return rcb();
            }

            if (!describeCacheClusters.data.length) {
                helpers.addResult(results, 0, 'No ElastiCache cluster found', region);
                return rcb();
            }
           
            for (var cluster of describeCacheClusters.data) {
                if (!cluster.ARN || !cluster.Engine) continue;

                var resource = cluster.ARN;

                if (cluster.CacheNodeType && cluster.CacheNodeType.length && cluster.Engine &&
                    config.elasticache_desired_node_type.includes(cluster.CacheNodeType)) {
                    helpers.addResult(results, 0,
                        `${cluster.Engine} cluster has desired node type: ${cluster.CacheNodeType}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `${cluster.Engine} cluster does not have desired node type: ${cluster.CacheNodeType}`,
                        region, resource);
                }
            }
            rcb();  
        }, function(){
            callback(null, results, source);
        });
    }
};

var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElastiCache Instance Generation',
    category: 'ElastiCache',
    domain: 'Databases',
    description: 'Ensure that all ElastiCache clusters provisioned within your AWS account are using the latest generation of instances',
    more_info: 'Using the latest generation of Amazon ElastiCache instances instances will benefit clusters for higher hardware performance, ' +
        'better support for latest Memcached and Redis in-memory engines versions and lower costs.',
    link: 'https://aws.amazon.com/elasticache/previous-generation/',
    recommended_action: 'Upgrade ElastiCache instance generaion to the latest available generation.',
    apis: ['ElastiCache:describeCacheClusters'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var previousGen = [
            'cache.m1.small',
            'cache.m1.medium',
            'cache.m1.large',
            'cache.m1.xlarge',
            'cache.m2.xlarge',
            'cache.m2.2xlarge',
            'cache.m2.4xlarge',
            'cache.c1.xlarge',
            'cache.t1.micro',
            'cache.m3.medium',
            'cache.m3.large',
            'cache.m3.xlarge',
            'cache.m3.2xlarge',
            'cache.r3.large',
            'cache.r3.xlarge',
            'cache.r3.2xlarge',
            'cache.r3.4xlarge',
            'cache.r3.8xlarge'
        ];

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
            
            for (var cluster of describeCacheClusters.data) {
                if (!cluster.ARN) continue;

                var resource = cluster.ARN;

                if (cluster.CacheNodeType) {
                    var generation = cluster.CacheNodeType;

                    if (previousGen.includes(generation)) {
                        helpers.addResult(results, 2,
                            'ElastiCache cluster is running previoud generation instance node: ' + generation,
                            region, resource);
                    } else {
                        helpers.addResult(results, 0,
                            'ElastiCache cluster is running current generation Instance Node: ' + generation,
                            region, resource);
                    }
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
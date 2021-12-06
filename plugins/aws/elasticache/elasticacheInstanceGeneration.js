var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElastiCache Instance Generation',
    category: 'ElastiCache',
    domain: 'Databases',
    description: 'Ensure that all ElastiCache clusters provisioned within your AWS account are using the latest generation of instances',
    more_info: 'Using the latest generation of Amazon ElastiCache instances instead of the previous generation instances will upgrade your clusters for higher hardware performance,'+
        'better support for latest Memcached and Redis in-memory engines versions and lower costs for compute power and network bandwidth.',
    link: 'https://aws.amazon.com/elasticache/previous-generation/',
    recommended_action: 'Upgrade the generation of instances on all ELastiCache clusters to the latest available generation.',
    apis: ['ElastiCache:describeCacheClusters'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var deprecatedGenerations = {
            'cache.m1.small'  :'Standard', 
            'cache.m1.medium' :'Standard',
            'cache.m1.large'  :'Standard',
            'cache.m1.xlarge' :'Standard',
            'cache.m2.xlarge' :'MemoryOptimized',
            'cache.m2.2xlarge':'MemoryOptimized',
            'cache.m2.4xlarge':'MemoryOptimized',
            'cache.c1.xlarge' :'ComputeOptimized',
            'cache.t1.micro'  :'Micro',
        };

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
                    let generationDeprecationType = (deprecatedGenerations[generation]) ? deprecatedGenerations[generation] : null;
                    
                    if (generationDeprecationType) {
                        helpers.addResult(results, 2,
                            'ElastiCache cluster is running generation instance node: ' + generation + ' which is currently depricated',
                            region, resource);
                    } else {
                        helpers.addResult(results, 0,
                            'ElastiCache cluster is running a current generation of Instance Node: ' + generation,
                            region, resource);
                    }
                } else {
                    helpers.addResult(results, 2, 'Unknown Instance Generation found', region, resource);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
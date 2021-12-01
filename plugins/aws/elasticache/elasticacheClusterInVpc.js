var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElastiCache Cluster In VPC',
    category: 'ElastiCache',
    domain: 'Databases',
    description: 'Ensure that your ElastiCache clusters are provisioned within the AWS EC2-VPC platform instead of EC2-Classic platform .',
    more_info: 'AWS ElastiCache clusters using EC2-VPC platform instead of EC2-Classic can bring multiple advantages such as better networking infrastructure, much more flexible control over access security .',
    link: 'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/VPCs.EC.html',
    recommended_action: 'ElastiCache clusters Available in VPC',
    apis: ['ElastiCache:describeCacheClusters'],
    run: function(cache, settings, callback) {
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
            
            for (var cluster of describeCacheClusters.data) {
                if (!cluster.ARN) continue;

                var resource = cluster.ARN;

                if (cluster.CacheSubnetGroupName &&
                    cluster.CacheSubnetGroupName.length) {
                    helpers.addResult(results, 0,
                        `ElastiCache cluster  "${cluster.CacheClusterId}" is in VPC`, region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `ElastiCache cluster  "${cluster.CacheClusterId}" is not in VPC`, region, resource);
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};


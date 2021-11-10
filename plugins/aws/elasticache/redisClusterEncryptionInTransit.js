var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElastiCache Redis Cluster Encryption In-Transit',
    category: 'ElastiCache',
    domain: 'Databases',
    description: 'Ensure that your AWS ElastiCache Redis clusters are encrypted in order to meet security and compliance requirements.',
    more_info: 'Working with production data it is highly recommended to implement encryption in order to protect it from unauthorized access and fulfill compliance requirements for data-in-transit encryption within your organization',
    link: 'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/WhatIs.html',
    recommended_action: 'Enable encryption for ElastiCache cluster data-in-transit.',
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
            
            for (var c in describeCacheClusters.data) {
                var cluster = describeCacheClusters.data[c];
                var resource = cluster.ARN;

                if (!cluster.Engine === 'redis'){
                    helpers.addResult(results, 2, `Encryption is not supported for ${cluster.Engine}`, region);
                    continue ;
                }

                if (cluster.TransitEncryptionEnabled) {
                    helpers.addResult(results, 0,
                        'Encryption is enabled for In-Transit Cluster :' + cluster.CacheClusterId, region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Encryption is not enabled for In-Transit Cluster :' + cluster.CacheClusterId, region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};

var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElastiCache Cluster Has Tags',
    category: 'ElastiCache',
    domain: 'Databases',
    severity: 'Low',
    description: 'Ensure that ElastiCache clusters have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    link: 'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/Tagging-Resources.html',
    recommended_action: 'Modify ElastiCache cluster and add tags.',
    apis: ['ElastiCache:describeCacheClusters', 'ResourceGroupsTaggingAPI:getResources'],
    realtime_triggers: ['elasticache:CreateCacheCluster', 'elasticache:DeleteCacheCluster', 'elasticache:AddTagsToResource', 'elasticache:RemoveTagsToResource'],

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

            const ARNList = [];
            for (var cluster of describeCacheClusters.data) {
                ARNList.push(cluster.ARN);
            }
            helpers.checkTags(cache, 'ElastiCache cluster', ARNList, region, results, settings);
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};

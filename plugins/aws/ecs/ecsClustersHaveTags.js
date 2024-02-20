var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ECS Cluster Has Tags',
    category: 'ECS',
    domain: 'Compute',
    severity: 'Low',
    description: 'Ensure that AWS ECS Clusters have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    link: 'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-using-tags.html',
    recommended_action: 'Modify ECS Cluster and add tags.',
    apis: ['ECS:listClusters', 'ResourceGroupsTaggingAPI:getResources'],
    realtime_triggers: ['ecs:CreateCluster', 'ecs:TagResource', 'ecs:UntagResource', 'ecs:DeleteCluster'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.ecs, function(region, rcb) {
            var listClusters = helpers.addSource(cache, source,
                ['ecs', 'listClusters', region]);

            if (!listClusters) return rcb();

            if (listClusters.err || !listClusters.data) {
                helpers.addResult(results, 3,
                    'Unable to query for ECS clusters: ' + helpers.addError(listClusters), region);
                return rcb();
            }

            if (!listClusters.data.length){
                helpers.addResult(results, 0, 'No ECS clusters present', region);
                return rcb();
            }

            helpers.checkTags(cache,'ECS clsuters', listClusters.data, region, results, settings);

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
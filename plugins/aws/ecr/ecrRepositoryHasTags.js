var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ECR Repository Has Tags',
    category: 'ECR',
    domain: 'Containers',
    severity: 'Low',
    description: 'Ensure that Amazon ECR repositories have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    link: 'https://docs.aws.amazon.com/AmazonECR/latest/userguide/ecr-using-tags.html',
    recommended_action: 'Modify ECR repository and add tags.',
    apis: ['ECR:describeRepositories', 'ResourceGroupsTaggingAPI:getResources'],
    realtime_triggers: ['ecr:CreateRepository', 'ecr:TagResource', 'ecr:UntagResource', 'ecr:DeleteRepository'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.ecr, function(region, rcb) {
            var describeRepositories = helpers.addSource(cache, source,
                ['ecr', 'describeRepositories', region]);

            if (!describeRepositories) return rcb();

            if (describeRepositories.err || !describeRepositories.data) {
                helpers.addResult(results, 3,
                    'Unable to query for ECR repositories: ' + helpers.addError(describeRepositories), region);
                return rcb();
            }

            if (!describeRepositories.data.length) {
                helpers.addResult(results, 0, 'No ECR repositories present', region);
                return rcb();
            }
            const ecrARN = [];
            for (let repo of describeRepositories.data) {
                if (!repo.repositoryArn) continue;
                ecrARN.push(repo.repositoryArn);
            }
            helpers.checkTags(cache, 'ECR repository', ecrARN, region, results, settings);

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

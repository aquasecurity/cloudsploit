var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ECR Has Tags',
    category: 'ECR',
    domain: 'Containers',
    description: 'Ensure that ECR repositories have tags.',
    more_info: 'ECR repositories should be configured to prevent overwriting of image tags to avoid potentially-malicious images from being deployed to live environments.',
    link: 'https://docs.aws.amazon.com/AmazonECR/latest/userguide/ecr-using-tags.html',
    recommended_action: 'Modify ECR repository and add tags.',
    apis: ['ECR:describeRepositories', 'ECR:listTagsForResource'],

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

            for (let repo of describeRepositories.data) {
                if (!repo.repositoryArn) continue;

                var listTagsForResource = helpers.addSource(cache, source,
                    ['ecr', 'listTagsForResource', region, repo.repositoryArn]);

                if (!listTagsForResource || listTagsForResource.err || !listTagsForResource.data) {
                    
                    helpers.addResult(results, 3,
                        'Unable to list tags for resources: ' + helpers.addError(listTagsForResource), region, repo.repositoryArn);
                    continue;
                }
                if (!listTagsForResource.data.tags || !listTagsForResource.data.tags.length){
                    helpers.addResult(results, 2, 'ECR repositories does not have tags', region, repo.repositoryArn);
                } else {
                    helpers.addResult(results, 0, 'ECR repositories has tags', region, repo.repositoryArn);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

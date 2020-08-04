var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ECR Repository Tag Immutability',
    category: 'ECR',
    description: 'Ensures ECR repository image tags cannot be overwritten',
    more_info: 'ECR repositories should be configured to prevent overwriting of image tags to avoid potentially-malicious images from being deployed to live environments.',
    link: 'https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-tag-mutability.html',
    recommended_action: 'Update ECR registry configurations to ensure image tag mutability is set to immutable.',
    apis: ['ECR:describeRepositories'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.ecr, function(region, rcb) {
            var describeRepositories = helpers.addSource(cache, source,
                ['ecr', 'describeRepositories', region]);

            if (!describeRepositories) return rcb();

            if (describeRepositories.err || !describeRepositories.data) {
                helpers.addResult(
                    results, 3,
                    'Unable to query for ECR repositories: ' + helpers.addError(describeRepositories), region);
                return rcb();
            }

            if (describeRepositories.data.length === 0) {
                helpers.addResult(results, 0, 'No ECR repositories present', region);
                return rcb();
            }

            for (var r in describeRepositories.data) {
                var repository = describeRepositories.data[r];
                var arn = repository.repositoryArn;
                var immutability = repository.imageTagMutability;

                if (immutability == 'IMMUTABLE') {
                    helpers.addResult(results, 0,
                        'ECR repository mutability setting is set to IMMUTABLE',
                        region, arn);
                } else {
                    helpers.addResult(results, 2,
                        'ECR repository mutability setting is set to MUTABLE',
                        region, arn);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

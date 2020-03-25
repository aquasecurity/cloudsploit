var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ECR Repository Policy',
    category: 'ECR',
    description: 'Ensures ECR repository policies do not enable global or public access to images',
    more_info: 'ECR repository policies should limit access to images to known IAM entities and AWS accounts and avoid the use of account-level wildcards.',
    link: 'https://docs.aws.amazon.com/AmazonECR/latest/userguide/RepositoryPolicyExamples.html',
    recommended_action: 'Update the repository policy to limit access to known IAM entities.',
    apis: ['ECR:describeRepositories', 'ECR:getRepositoryPolicy'],
    settings: {
        ecr_check_global_principal: {
            name: 'ECR Check Global Principal',
            description: 'When set to true ECR repositories with a global principal will be marked as failing',
            regex: '^(true|false)$',
            default: 'true'
        },
        ecr_check_cross_account_principal: {
            name: 'ECR Check Cross-Account Principal',
            description: 'When set to true ECR repositories with a cross account principal will be marked as failing',
            regex: '^(true|false)$',
            default: 'true'
        }
    },

    run: function (cache, settings, callback) {
        var config = {
            ecr_check_global_principal: settings.ecr_check_global_principal || this.settings.ecr_check_global_principal.default,
            ecr_check_cross_account_principal: settings.ecr_check_cross_account_principal || this.settings.ecr_check_cross_account_principal.default
        };

        config.ecr_check_global_principal = (config.ecr_check_global_principal == 'true');
        config.ecr_check_cross_account_principal = (config.ecr_check_cross_account_principal == 'true');

        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.ecr, function (region, rcb) {
            var describeRepositories = helpers.addSource(cache, source,
                ['ecr', 'describeRepositories', region]);

            if (!describeRepositories) return rcb();

            if (describeRepositories.err || !describeRepositories.data) {
                helpers.addResult(
                    results, 3,
                    'Unable to query for ECR repositories: ' + helpers.addError(describeRepositories), region);
                return rcb();
            }

            if(describeRepositories.data.length === 0){
                helpers.addResult(results, 0, 'No ECR repositories present', region);
                return rcb();
            }

            for (r in describeRepositories.data) {
                var repository = describeRepositories.data[r];
                var name = repository.repositoryName;
                var arn = repository.repositoryArn;
                var registryId = repository.registryId;

                var getRepositoryPolicy = helpers.addSource(cache, source,
                    ['ecr', 'getRepositoryPolicy', region, name]);

                if (getRepositoryPolicy && getRepositoryPolicy.err &&
                    getRepositoryPolicy.err.code &&
                    getRepositoryPolicy.err.code == 'RepositoryPolicyNotFoundException') {
                    helpers.addResult(results, 0, 'ECR registry does not have a custom policy', region, arn);
                    continue;
                }

                if (!getRepositoryPolicy || getRepositoryPolicy.err ||
                    !getRepositoryPolicy.data || !getRepositoryPolicy.data.policyText) {
                    helpers.addResult(
                        results, 3,
                        'Unable to get ECR registry policy: ' + helpers.addError(getRepositoryPolicy),
                        region, arn);
                    continue;
                }

                var policy = helpers.normalizePolicyDocument(getRepositoryPolicy.data.policyText);

                if (!policy || !policy.length) {
                    helpers.addResult(results, 0,
                        'ECR repository does not have a custom policy',
                        region, arn);
                    continue;
                }

                var found = [];
                var result = 0;

                for (s in policy) {
                    var statement = policy[s];

                    if (statement.Effect == 'Allow') {
                        // Check for aws account ID condition
                        if (statement.Condition && statement.Condition.StringEquals &&
                            statement.Condition.StringEquals['aws:SourceAccount']) {
                            var srcAcct = statement.Condition.StringEquals['aws:SourceAccount'];
                            if (typeof srcAcct === 'string' && srcAcct == registryId) continue;
                            if (Array.isArray(srcAcct) && srcAcct.length == 1 && srcAcct[0] == registryId) continue;
                        }

                        if (helpers.globalPrincipal(statement.Principal) && config.ecr_check_global_principal) {
                            // Check for global access
                            found.push('Repository allows global access for actions: ' + statement.Action.join(', ') + '.');
                            if (result < 2) result = 2;
                        } else if (helpers.crossAccountPrincipal(statement.Principal, registryId) && config.ecr_check_cross_account_principal) {
                            // Check for cross-account access
                            found.push('Repository allows cross-account access for actions: ' + statement.Action.join(', ') + '.');
                            if (result < 2) result = 2;
                        }
                    }
                }

                if (found.length) {
                    helpers.addResult(results, result,
                        found.join(' '),
                        region, arn);
                } else {
                    helpers.addResult(results, 0,
                        'ECR repository policy does not have overly permissive statements',
                        region, arn);
                }
            }

            rcb();
        }, function () {
            callback(null, results, source);
        });
    }
};

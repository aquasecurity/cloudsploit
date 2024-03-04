var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Cloud Function All Users Policy',
    category: 'Cloud Functions',
    domain: 'Serverless',
    severity: 'High',
    description: 'Ensure cloud functions are not anonymously or publicly accessible.',
    more_info: 'Using Cloud Identity and Access Management (IAM), you can control access to the cloud functions. As a security best practice, ensure the access is not allowed to "allUsers" or "allAuthentictaedUsers" to avoid data leaks and other security risks.',
    link: 'https://cloud.google.com/functions/docs/concepts/iam',
    recommended_action: 'Ensure that each cloud function is configured so that no member is set to allUsers or allAuthenticatedUsers.',
    apis: ['functions:list', 'functions:getIamPolicy'],
    realtime_triggers: ['functions.CloudFunctionsService.UpdateFunction', 'functions.CloudFunctionsService.CreateFunction', 'functions.CloudFunctionsService.DeleteFunction'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();
        
        async.each(regions.functions, (region, rcb) => {
            var functions = helpers.addSource(cache, source,
                ['functions', 'list', region]);

            if (!functions) return rcb();

            if (functions.err || !functions.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Google Cloud Functions: ' + helpers.addError(functions), region, null, null, functions.err);
                return rcb();
            }

            if (!functions.data.length) {
                helpers.addResult(results, 0, 'No Google Cloud functions found', region);
                return rcb();
            }

            let functionPolicies = helpers.addSource(cache, source,
                ['functions', 'getIamPolicy', region]);

            if (!functionPolicies) return rcb();

            if (functionPolicies.err || !functionPolicies.data) {
                helpers.addResult(results, 3, 'Unable to query cloud function policies: ' + helpers.addError(functionPolicies), region, null, null, functionPolicies.err);
                return rcb();
            }

            if (!functionPolicies.data.length) {
                helpers.addResult(results, 0, 'No Google Cloud functions found', region);
                return rcb();
            }


            functions.data.forEach(func => {
                if (!func.name) return;

                let funcPolicy = functionPolicies.data.find(policy => policy.parent && policy.parent.name && policy.parent.name == func.name);
                let hasAllUsers = false;

                if (funcPolicy.bindings &&
                    funcPolicy.bindings.length) {
                    funcPolicy.bindings.forEach(binding => {
                        if (binding.members &&
                           binding.members.length) {
                            binding.members.forEach(member => {
                                if (member === 'allUsers' ||
                                   member === 'allAuthenticatedUsers') {
                                    hasAllUsers = true;
                                }
                            });
                        }
                    });
                }
                if (hasAllUsers) {
                    helpers.addResult(results, 2,
                        'Cloud Function has anonymous or public access', region, func.name);
                } else {
                    helpers.addResult(results, 0,
                        'Cloud Function does not have anonymous or public access', region, func.name);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
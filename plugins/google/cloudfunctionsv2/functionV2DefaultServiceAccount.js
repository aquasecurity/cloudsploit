var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Cloud Function V2 Default Service Account',
    category: 'Cloud Functions',
    domain: 'Serverless',
    severity: 'Medium',
    description: 'Ensure that Cloud Functions V2 are not using the default service account.',
    more_info: 'Using the default service account for Cloud Functions V2 can lead to privilege escalation and overly permissive access. It is recommended to use a user-managed service account for each function in a project instead of the default service account. A managed service account allows more precise access control by granting only the necessary permissions through Identity and Access Management (IAM).',
    link: 'https://cloud.google.com/functions/docs/securing/function-identity',
    recommended_action: 'Ensure that no Cloud Functions V2 are using the default service account.',
    apis: ['functionsv2:list'],
    realtime_triggers: ['functions.CloudFunctionsService.UpdateFunction', 'functions.CloudFunctionsService.CreateFunction', 'functions.CloudFunctionsService.DeleteFunction'],
    
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();
        
        async.each(regions.functions, (region, rcb) => {
            var functions = helpers.addSource(cache, source,
                ['functionsv2', 'list', region]);

            if (!functions) return rcb();

            if (functions.err || !functions.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Google Cloud functions: ' + helpers.addError(functions), region, null, null, functions.err);
                return rcb();
            }

            if (!functions.data.length) {
                helpers.addResult(results, 0, 'No Google Cloud functions found', region);
                return rcb();
            }

            functions.data.forEach(func => {
                if (!func.name) return;

                if (!func.buildConfig || !func.buildConfig.functionTarget) return;

                let serviceAccountEmail = func.template && func.template.serviceAccount 
                    ? func.template.serviceAccount 
                    : null;

                if (serviceAccountEmail && serviceAccountEmail.endsWith('@appspot.gserviceaccount.com')) {
                    helpers.addResult(results, 2,
                        'Cloud Function is using default service account', region, func.name);
                } else if (serviceAccountEmail) {
                    helpers.addResult(results, 0,
                        'Cloud Function is not using default service account', region, func.name);
                } else {
                    helpers.addResult(results, 2,
                        'Cloud Function does not have a service account configured', region, func.name);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};


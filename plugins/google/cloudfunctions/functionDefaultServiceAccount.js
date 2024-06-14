var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Cloud Function Default Service Account',
    category: 'Cloud Functions',
    domain: 'Serverless',
    severity: 'Low',
    description: 'Ensures that Cloud Functions are not using the default service account.',
    more_info: 'Cloud Functions should use customized service accounts that have minimal privileges to run. Default service account has the editor role permissions. Due to security reasons it should not be used for any cloud function.',
    link: 'https://cloud.google.com/functions/docs/securing',
    recommended_action: 'Ensure that no Cloud Functions are using the default service account.',
    apis: ['functions:list'],
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

            functions.data.forEach(func => {
                if (!func.name) return;

                if (func.serviceAccountEmail && func.serviceAccountEmail.endsWith('@appspot.gserviceaccount.com')) {
                    helpers.addResult(results, 2,
                        'Cloud Function is using default service account', region, func.name);
                } else {
                    helpers.addResult(results, 0,
                        'Cloud Function is not using default service account', region, func.name);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
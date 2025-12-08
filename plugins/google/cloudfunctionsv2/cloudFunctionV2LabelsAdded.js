var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Cloud Function V2 Labels Added',
    category: 'Cloud Functions',
    domain: 'Serverless',
    severity: 'Low',
    description: 'Ensure that all Cloud Functions V2 have labels added.',
    more_info: 'Labels are a lightweight way to group resources together that are related to or associated with each other. It is a best practice to label cloud resources to better organize and gain visibility into their usage.',
    link: 'https://cloud.google.com/functions/docs/configuring',
    recommended_action: 'Ensure labels are added to all Cloud Functions V2.',
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

                let userLabels = func.labels ? Object.keys(func.labels).filter(key => !key.startsWith('goog-')) : [];
                
                if (userLabels.length) {
                    helpers.addResult(results, 0,
                        `${userLabels.length} labels found for Cloud Function`, region, func.name);
                } else {
                    helpers.addResult(results, 2,
                        'Cloud Function does not have any labels', region, func.name);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};


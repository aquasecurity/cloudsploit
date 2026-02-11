var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'HTTP Trigger Require HTTPS V2',
    category: 'Cloud Functions',
    domain: 'Serverless',
    severity: 'Medium',
    description: 'Ensure that Cloud Functions V2 are configured to require HTTPS for HTTP invocations.',
    more_info: 'You can make your Google Cloud Functions V2 calls secure by making sure that they require HTTPS.',
    link: 'https://cloud.google.com/functions/docs/writing/http',
    recommended_action: 'Ensure that your Google Cloud Functions V2 always require HTTPS.',
    apis: ['functionsv2:list'],
    realtime_triggers: ['functions.CloudFunctionsService.UpdateFunction','functions.CloudFunctionsService.DeleteFunction', 'functions.CloudFunctionsService.CreateFunction'],

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

            functions.data.forEach(funct => {
                if (!funct.name) return;

                if (!funct.buildConfig || !funct.buildConfig.functionTarget) return;

                let triggerType = funct.template && funct.template.annotations ? funct.template.annotations['cloudfunctions.googleapis.com/trigger-type'] : null;

                if (triggerType === 'HTTP_TRIGGER' || funct.uri) {
                    if (funct.uri && funct.uri.startsWith('https://')) {
                        helpers.addResult(results, 0,
                            'Cloud Function is configured to require HTTPS for HTTP invocations', region, funct.name);
                    } else {
                        helpers.addResult(results, 2,
                            'Cloud Function is not configured to require HTTPS for HTTP invocations', region, funct.name);
                    }
                } else {
                    helpers.addResult(results, 0,
                        'Cloud Function trigger type is not HTTP', region, funct.name);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};


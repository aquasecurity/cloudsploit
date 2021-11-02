var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'HTTP Trigger require HTTPS',
    category: 'Cloud Functions',
    description: 'Ensure that Cloud Functions are configured to require HTTPS for HTTP invocations.',
    more_info: 'You can make your google cloud functions call secure by making sure that they require HTTPS.',
    link: 'https://cloud.google.com/functions/docs/writing/http',
    recommended_action: 'Ensure that your Google Cloud functions always require HTTPS.',
    apis: ['functions:list', 'projects:get'],

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

            functions.data.forEach(funct => {
                if (!funct.name) return;

                if (funct.httpsTrigger) {
                    if (funct.httpsTrigger.securityLevel && funct.httpsTrigger.securityLevel == 'SECURE_ALWAYS') {
                        helpers.addResult(results, 0, 'Cloud Function is configured to require HTTPS for HTTP invocations',
                            region, funct.name);
                    } else {
                        helpers.addResult(results, 2, 'Cloud Function is not configured to require HTTPS for HTTP invocations', region, funct.name);
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
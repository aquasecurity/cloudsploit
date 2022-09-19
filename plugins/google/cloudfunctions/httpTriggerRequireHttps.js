var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'HTTP Trigger require HTTPS',
    category: 'Cloud Functions',
    domain: 'Serverless',
    description: 'Ensure that Cloud Functions are configured to require HTTPS for HTTP invocations.',
    more_info: 'You can make your google cloud functions call secure by making sure that they require HTTPS.',
    link: 'https://cloud.google.com/functions/docs/writing/http',
    recommended_action: 'Ensure that your Google Cloud functions always require HTTPS.',
    apis: ['functions:list'],
    remediation_min_version: '202207282132',
    remediation_description: 'All Google Cloud Functions will be configured to require HTTPS for HTTP invocations.',
    apis_remediate: ['functions:list', 'projects:get'],
    actions: {remediate:['CloudFunctionsService.UpdateFunction'], rollback:['CloudFunctionsService.UpdateFunction']},
    permissions: {remediate: ['cloudfunctions.functions.update'], rollback: ['cloudfunctions.functions.create	']},
    realtime_triggers: ['google.cloud.functions.v1.CloudFunctionsService.UpdateFunction', 'google.cloud.functions.v1.CloudFunctionsService.CreateFunction'],

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
    },
    remediate: function(config, cache, settings, resource, callback) {
        var remediation_file = settings.remediation_file;

        // inputs specific to the plugin
        var pluginName = 'httpTriggerRequireHttps';
        var baseUrl = 'https://cloudfunctions.googleapis.com/v1/{resource}?updateMask=httpsTrigger.securityLevel';
        var method = 'PATCH';
        var putCall = this.actions.remediate;

        // create the params necessary for the remediation
        var body = {
            httpsTrigger: {
                securityLevel: 'SECURE_ALWAYS'
            }
        };
        // logging
        remediation_file['pre_remediate']['actions'][pluginName][resource] = {
            'httpTriggerRequireHttps': 'Disabled'
        };

        helpers.remediatePlugin(config, method, body, baseUrl, resource, remediation_file, putCall, pluginName, function(err, action) {
            if (err) return callback(err);
            if (action) action.action = putCall;


            remediation_file['post_remediate']['actions'][pluginName][resource] = action;
            remediation_file['remediate']['actions'][pluginName][resource] = {
                'Action': 'Enabled'
            };

            callback(null, action);
        });
    }

};
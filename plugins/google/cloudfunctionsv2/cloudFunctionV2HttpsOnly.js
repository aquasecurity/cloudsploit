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
    remediation_min_version: '202207282132',
    remediation_description: 'All Google Cloud Functions V2 will be configured to require HTTPS for HTTP invocations.',
    apis_remediate: ['functionsv2:list', 'projects:get'],
    actions: {remediate:['CloudFunctionsService.UpdateFunction'], rollback:['CloudFunctionsService.UpdateFunction']},
    permissions: {remediate: ['cloudfunctions.functions.update'], rollback: ['cloudfunctions.functions.create']},
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

                if (!funct.environment || funct.environment !== 'GEN_2') return;

                let serviceConfig = funct.serviceConfig || {};

                if (serviceConfig.uri) {
                    if (serviceConfig.securityLevel && serviceConfig.securityLevel == 'SECURE_ALWAYS') {
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
    },
    remediate: function(config, cache, settings, resource, callback) {
        var remediation_file = settings.remediation_file;

        // inputs specific to the plugin
        var pluginName = 'httpTriggerRequireHttps';
        var baseUrl = 'https://cloudfunctions.googleapis.com/v2/{resource}?updateMask=serviceConfig.securityLevel';
        var method = 'PATCH';
        var putCall = this.actions.remediate;

        // create the params necessary for the remediation
        var body = {
            serviceConfig: {
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


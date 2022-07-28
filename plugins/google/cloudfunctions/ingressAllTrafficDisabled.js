var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Ingress All Traffic Disabled',
    category: 'Cloud Functions',
    domain: 'Serverless',
    description: 'Ensure that Cloud Functions are configured to allow only internal traffic or traffic from Cloud Load Balancer.',
    more_info: 'You can secure your google cloud functions by implementing network based access control.',
    link: 'https://cloud.google.com/functions/docs/securing/authenticating',
    recommended_action: 'Ensure that your Google Cloud functions do not allow external traffic from the internet.',
    apis: ['functions:list'],
    remediation_min_version: '202207282132',
    remediation_description: 'All Google Cloud Functions will be configured to allow only internal traffic and traffic from Cloud Load Balancer.',
    apis_remediate: ['functions:list'],
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

            functions.data.forEach(func => {
                if (!func.name) return;

                if (func.ingressSettings && func.ingressSettings.toUpperCase() == 'ALLOW_ALL') {
                    helpers.addResult(results, 2, 'Cloud Function is configured to allow all traffic', region, func.name);
                } else {
                    helpers.addResult(results, 0, 'Cloud Function is configured to allow only internal and CLB traffic', region, func.name);
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
        var pluginName = 'ingressAllTrafficDisabled';
        var baseUrl = 'https://cloudfunctions.googleapis.com/v1/{resource}?updateMask=ingressSettings';
        var method = 'PATCH';
        var putCall = this.actions.remediate;

        // create the params necessary for the remediation
        var body = {
            ingressSettings: 'ALLOW_INTERNAL_AND_GCLB'
        };
        // logging
        remediation_file['pre_remediate']['actions'][pluginName][resource] = {
            'ingressAllTraffic': 'Enabled'
        };

        helpers.remediatePlugin(config, method, body, baseUrl, resource, remediation_file, putCall, pluginName, function(err, action) {
            if (err) return callback(err);
            if (action) action.action = putCall;


            remediation_file['post_remediate']['actions'][pluginName][resource] = action;
            remediation_file['remediate']['actions'][pluginName][resource] = {
                'Action': 'Disabled'
            };

            callback(null, action);
        });
    }
};
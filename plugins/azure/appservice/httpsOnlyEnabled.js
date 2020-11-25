const async = require('async');

const helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'HTTPS Only Enabled',
    category: 'App Service',
    description: 'Ensures HTTPS Only is enabled for App Services, redirecting all HTTP traffic to HTTPS',
    more_info: 'Enabling HTTPS Only traffic will redirect all non-secure HTTP requests to HTTPS. HTTPS uses the SSL/TLS protocol to provide a secure connection.',
    recommended_action: 'Enable HTTPS Only support SSL settings for all App Services',
    link: 'https://docs.microsoft.com/en-us/azure/app-service/app-service-web-tutorial-custom-ssl#enforce-https',
    apis: ['webApps:list'],
    remediation_min_version: '202011201836',
    remediation_description: 'The HTTPS-only option will be enabled for the web app',
    apis_remediate: ['webApps:list'],
    actions: {remediate:['webApps:write'], rollback:['webApps:write']},
    permissions: {remediate: ['webApps:write'], rollback: ['webApps:write']},
    realtime_triggers: ['microsoftweb:sites:write'],
    compliance: {
        hipaa: 'HIPAA requires all data to be transmitted over secure channels. ' +
                'App Service HTTPS redirection should be used to ensure site visitors ' +
                'are always connecting over a secure channel.',
        pci: 'All card holder data must be transmitted over secure channels. ' +
                'App Service HTTPS redirection should be used to ensure site visitors ' +
                'are always connecting over a secure channel.'
    },

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.webApps, function(location, rcb) {

            const webApps = helpers.addSource(
                cache, source, ['webApps', 'list', location]
            );

            if (!webApps) return rcb();

            if (webApps.err || !webApps.data) {
                helpers.addResult(results, 3,
                    'Unable to query App Service: ' + helpers.addError(webApps), location);
                return rcb();
            }

            if (!webApps.data.length) {
                helpers.addResult(results, 0, 'No existing App Services found', location);
                return rcb();
            }

            webApps.data.forEach(function(webApp) {
                if (webApp.httpsOnly) {
                    helpers.addResult(results, 0, 'The App Service has HTTPS Only enabled', location, webApp.id);
                } else {
                    helpers.addResult(results, 2, 'The App Service does not have HTTPS Only enabled', location, webApp.id);
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    },
    remediate: function(config, cache, settings, resource, callback) {
        var remediation_file = settings.remediation_file;
        var putCall = this.actions.remediate;

        // inputs specific to the plugin
        var pluginName = 'httpsOnlyEnabled';
        var baseUrl = 'https://management.azure.com/{resource}?api-version=2019-08-01';
        var method = 'PUT';

        // for logging purposes
        var webAppNameArr = resource.split('/');
        var webAppName = webAppNameArr[webAppNameArr.length - 1];

        // create the params necessary for the remediation
        if (settings.region) {
            var body = {
                'location': settings.region,
                'properties': {
                    'httpsOnly': true
                }

            };

            // logging
            remediation_file['pre_remediate']['actions'][pluginName][resource] = {
                'HttpsOnly': 'Disabled',
                'WebApp': webAppName
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
        } else {
            callback('No region found');
        }
    }
};

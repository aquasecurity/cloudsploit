var async = require('async');

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Identity Enabled',
    category: 'App Service',
    description: 'Ensures a system or user assigned managed identity is enabled to authenticate to App Services without storing credentials in the code.',
    more_info: 'Maintaining cloud connection credentials in code is a security risk. Credentials should never appear on developer workstations and should not be checked into source control. Managed identities for Azure resources provides Azure services with a managed identity in Azure AD which can be used to authenticate to any service that supports Azure AD authentication, without having to include any credentials in code.',
    recommended_action: 'Enable system or user-assigned identities for all App Services and avoid storing credentials in code.',
    link: 'https://docs.microsoft.com/en-us/azure/app-service/overview-managed-identity',
    apis: ['webApps:list'],
    remediation_min_version: '202101041500',
    remediation_description: 'The web app will be assigned a system manager identity',
    apis_remediate: ['webApps:list'],
    actions: {remediate:['webApps:update'], rollback:['webApps:update']},
    permissions: {remediate: ['webApps:update'], rollback: ['webApps:update']},
    realtime_triggers: ['microsoftweb:sites:write'],

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
                if (webApp.identity) {
                    helpers.addResult(results, 0, 'The App Service has identities assigned', location, webApp.id);
                } else {
                    helpers.addResult(results, 2, 'The App Service does not have an identity assigned', location, webApp.id);
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
        var pluginName = 'identityEnabled';
        var baseUrl = 'https://management.azure.com/{resource}?api-version=2019-08-01';
        var method = 'PATCH';

        // for logging purposes
        var webAppNameArr = resource.split('/');
        var webAppName = webAppNameArr[webAppNameArr.length - 1];

        // create the params necessary for the remediation
        if (settings.region) {
            var body = {
                'location': settings.region,
                'identity': {
                    'type': 'SystemAssigned'
                }

            };

            // logging
            remediation_file['pre_remediate']['actions'][pluginName][resource] = {
                'ManagedIdentity': 'Disabled',
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

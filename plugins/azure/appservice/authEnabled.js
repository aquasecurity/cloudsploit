const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Authentication Enabled',
    category: 'App Service',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Ensures Authentication is enabled for App Services, redirecting unauthenticated users to the login page.',
    more_info: 'Enabling authentication will redirect all unauthenticated requests to the login page. It also handles authentication of users with specific providers (Azure Active Directory, Facebook, Google, Microsoft Account, and Twitter).',
    recommended_action: 'Enable App Service Authentication for all App Services.',
    link: 'https://learn.microsoft.com/en-us/azure/app-service/overview-authentication-authorization',
    apis: ['webApps:list', 'webApps:getAuthSettings'],
    remediation_min_version: '202104011300',
    remediation_description: 'The App Service Authentication option will be enabled for the web app',
    apis_remediate: ['webApps:list'],
    actions: {remediate:['webApps:updateAuthSettings'], rollback:['webApps:updateAuthSettings']},
    permissions: {remediate: ['webApps:updateAuthSettings'], rollback: ['webApps:updateAuthSettings']},
    realtime_triggers: ['microsoftweb:sites:write','microsoftweb:sites:delete','microsoftweb:sites:config:write','microsoftweb:sites:config:delete'],
    compliance: {
        hipaa: 'HIPAA requires all application access to be restricted to known users ' +
               'for auditing and security controls.',
        pci: 'Access to system components must be restricted to known users.'
    },
    settings: {
        whitelist_functions_for_auth_enabled: {
            name: 'Whitelist Functions For Authentication Enabled',
            description: 'List of comma separated functions which should be whitelisted to check',
            regex: '^.*$',
            default: 'aqua-agentless-scanner-continuous-onboarding',
        }
    },

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        let config = {
            whitelist_functions_for_auth_enabled: settings.whitelist_functions_for_auth_enabled || this.settings.whitelist_functions_for_auth_enabled.default
        };

        async.each(locations.webApps, function(location, rcb) {

            const webApps = helpers.addSource(
                cache, source, ['webApps', 'list', location]
            );

            if (!webApps) return rcb();

            if (webApps.err || !webApps.data) {
                helpers.addResult(results, 3,
                    'Unable to query for App Services: ' + helpers.addError(webApps), location);
                return rcb();
            }

            if (!webApps.data.length) {
                helpers.addResult(
                    results, 0, 'No existing App Services found', location);
                return rcb();
            }

            webApps.data.forEach(function(webApp) {
                if (webApp.kind && webApp.kind.includes('workflowapp')) return;

                if (webApp.name.includes(config.whitelist_functions_for_auth_enabled)) {
                    helpers.addResult(results, 0, 'The App Service is whitelisted', location, webApp.id);
                } else {

                    const authSettings = helpers.addSource(
                        cache, source, ['webApps', 'getAuthSettings', location, webApp.id]
                    );

                    if (!authSettings || authSettings.err || !authSettings.data) {
                        helpers.addResult(results, 3,
                            'Unable to query App Service: ' + helpers.addError(authSettings),
                            location, webApp.id);
                    } else {
                        if (authSettings.data.enabled) {
                            helpers.addResult(results, 0, 'App Service has App Service Authentication enabled', location, webApp.id);
                        } else {
                            helpers.addResult(results, 2, 'App Service does not have App Service Authentication enabled', location, webApp.id);
                        }
                    }
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
        var pluginName = 'authEnabled';
        var baseUrl = 'https://management.azure.com/{resource}/config/authsettings?api-version=2019-08-01';
        var method = 'PUT';

        // for logging purposes
        var webAppNameArr = resource.split('/');
        var webAppName = webAppNameArr[webAppNameArr.length - 1];

        // create the params necessary for the remediation
        if (settings.region) {
            var body = {
                'location': settings.region,
                'properties': {
                    'enabled': true
                }
            };

            // logging
            remediation_file['pre_remediate']['actions'][pluginName][resource] = {
                'AppAuthentication': 'Disabled',
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

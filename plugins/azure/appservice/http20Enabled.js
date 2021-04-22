const async = require('async');
const helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'HTTP 2.0 Enabled',
    category: 'App Service',
    description: 'Ensures the latest HTTP version is enabled for App Services',
    more_info: 'Enabling HTTP2.0 ensures that the App Service has the latest technology which improves server performance',
    recommended_action: 'Enable HTTP 2.0 support in the general settings for all App Services',
    link: 'https://azure.microsoft.com/en-us/blog/announcing-http-2-support-in-azure-app-service/',
    apis: ['webApps:list', 'webApps:listConfigurations'],
    remediation_min_version: '202103311945',
    remediation_description: 'The HTTP 2.0 option will be enabled for the web app',
    apis_remediate: ['webApps:list'],
    actions: {remediate:['webApps:updateConfiguration'], rollback:['webApps:updateConfiguration']},
    permissions: {remediate: ['webApps:updateConfiguration'], rollback: ['webApps:updateConfiguration']},
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
                    'Unable to query for App Services: ' + helpers.addError(webApps), location);
                return rcb();
            }

            if (!webApps.data.length) {
                helpers.addResult(
                    results, 0, 'No existing App Services found', location);
                return rcb();
            }

            webApps.data.forEach(function(webApp) {
                const webConfigs = helpers.addSource(
                    cache, source, ['webApps', 'listConfigurations', location, webApp.id]
                );

                if (!webConfigs || webConfigs.err || !webConfigs.data) {
                    helpers.addResult(results, 3,
                        'Unable to query App Service: ' + helpers.addError(webConfigs),
                        location, webApp.id);
                } else {
                    if (webConfigs.data[0] && webConfigs.data[0].http20Enabled) {
                        helpers.addResult(results, 0, 'App Service has HTTP 2.0 enabled', location, webApp.id);
                    } else {
                        helpers.addResult(results, 2, 'App Service does not have HTTP 2.0 enabled', location, webApp.id);
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
        var pluginName = 'http20Enabled';
        var baseUrl = 'https://management.azure.com/{resource}/config/web?api-version=2019-08-01';
        var method = 'PATCH';

        // for logging purposes
        var webAppNameArr = resource.split('/');
        var webAppName = webAppNameArr[webAppNameArr.length - 1];

        // create the params necessary for the remediation
        if (settings.region) {
            var body = {
                'location': settings.region,
                'properties': {
                    'http20Enabled': true
                }

            };

            // logging
            remediation_file['pre_remediate']['actions'][pluginName][resource] = {
                'Http2.0': 'Disabled',
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

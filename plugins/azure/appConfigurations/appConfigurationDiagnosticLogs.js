var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'App Configuration Diagnostic Logs',
    category: 'App Configuration',
    domain: 'Developer Tools',
    severity: 'Medium',
    description: 'Ensures that Azure App Configuration have diagnostic logs enabled.',
    more_info: 'Enabling diagnostic logging for App Configuration helps with performance monitoring, troubleshooting, and security optimization.',
    recommended_action: 'Enable diagnostic logging for all App Configurations.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-app-configuration/monitor-app-configuration?tabs=portal#monitoringdata',
    apis: ['appConfigurations:list','diagnosticSettings:listByAppConfigurations'],
    realtime_triggers: ['microsoftappconfiguration:configurationstores:write','microsoftinsights:diagnosticsettings:write','microsoftinsights:diagnosticsettings:delete','microsoftappconfiguration:configurationstores:delete'],
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.appConfigurations, function(location, rcb) {
            var appConfigurations = helpers.addSource(cache, source,
                ['appConfigurations', 'list', location]);

            if (!appConfigurations) return rcb();

            if (appConfigurations.err || !appConfigurations.data) {
                helpers.addResult(results, 3, 'Unable to query App Configuration: ' + helpers.addError(appConfigurations), location);
                return rcb();
            }

            if (!appConfigurations.data.length) {
                helpers.addResult(results, 0, 'No existing App Configurations found', location);
                return rcb();
            }

            for (let appConfiguration of appConfigurations.data) {
                if (!appConfiguration.id) continue;

                var diagnosticSettings = helpers.addSource(cache, source,
                    ['diagnosticSettings', 'listByAppConfigurations', location, appConfiguration.id]);

                if (!diagnosticSettings || diagnosticSettings.err || !diagnosticSettings.data) {
                    helpers.addResult(results, 3, `Unable to query for App Configuration diagnostic settings: ${helpers.addError(diagnosticSettings)}`,
                        location, appConfiguration.id);
                    continue;
                }

                var found = diagnosticSettings.data.find(ds => ds.logs && ds.logs.length);

                if (found) {
                    helpers.addResult(results, 0, 'App Configuration has diagnostic logs enabled', location, appConfiguration.id);
                } else {
                    helpers.addResult(results, 2, 'App Configuration does not have diagnostic logs enabled', location, appConfiguration.id);
                }

            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};

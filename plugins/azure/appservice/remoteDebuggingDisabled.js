var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Web Apps Remote Debugging Disabled',
    category: 'App Service',
    description: 'Ensures that Azure Web Apps have remote debugging disabled.',
    more_info: 'Remote debugging feature requires specific inbound ports to be opened which can increase chances of unauthorized access.',
    recommended_action: 'Remote debugging should be disabled for Azure Web Apps',
    link: 'https://docs.microsoft.com/en-us/azure/app-service/troubleshoot-dotnet-visual-studio',
    apis: ['webApps:list', 'webApps:listConfigurations'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.webApps, function(location, rcb) {
            const webApps = helpers.addSource(cache, source,
                ['webApps', 'list', location]);

            if (!webApps) return rcb();

            if (webApps.err || !webApps.data) {
                helpers.addResult(results, 3, 'Unable to query for Web Apps: ' + helpers.addError(webApps), location);
                return rcb();
            }

            if (!webApps.data.length) {
                helpers.addResult(results, 0, 'No existing Web Apps found', location);
                return rcb();
            }

            async.each(webApps.data, function(webApp, scb) {
                const configs = helpers.addSource(cache, source, 
                    ['webApps', 'listConfigurations', location, webApp.id]);

                if (!configs || configs.err || !configs.data || !configs.data.length) {
                    helpers.addResult(results, 3, 'Unable to query for Web App Configs: ' + helpers.addError(configs), location);
                    return scb();
                }

                const remoteDebugging = configs.data.some(config => config.remoteDebuggingEnabled);
                if (!remoteDebugging) {
                    helpers.addResult(results, 0, 'Remote debugging is disabled for web app', location, webApp.id);
                } else {
                    helpers.addResult(results, 2, 'Remote debugging is enabled for web app', location, webApp.id);
                } 
                scb();
            }, function() {
                rcb();
            });
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};

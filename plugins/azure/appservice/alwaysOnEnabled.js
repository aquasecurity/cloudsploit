var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Web Apps Always On Enabled',
    category: 'App Service',
    description: 'Ensures that Azure Web Apps have Always On feature enabled.',
    more_info: 'Always On feature keeps the app loaded even when there\'s no traffic. It\'s required for continuous WebJobs or for WebJobs that are triggered using a CRON expression.',
    recommended_action: 'Enable Always On feature for Azure Web Apps',
    link: 'https://docs.microsoft.com/en-us/azure/app-service/configure-common',
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
                if (webApp && webApp.kind && webApp.kind === 'functionapp') {
                    helpers.addResult(results, 0, 'Always On feature can not be configured for the function App', location, webApp.id);
                    return scb();
                }

                const configs = helpers.addSource(cache, source,
                    ['webApps', 'listConfigurations', location, webApp.id]);

                if (!configs || configs.err || !configs.data || !configs.data.length) {
                    helpers.addResult(results, 3, 'Unable to query for Web App Configs: ' + helpers.addError(configs), location);
                    return scb();
                }

                const alwaysOnEnabled = configs.data.some(config => config.alwaysOn);
                if (alwaysOnEnabled) {
                    helpers.addResult(results, 0, 'Always On feature is enabled for the Web App', location, webApp.id);
                } else {
                    helpers.addResult(results, 2, 'Always On feature is disabled for the Web App', location, webApp.id);
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

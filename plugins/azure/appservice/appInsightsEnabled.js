var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Web Apps Insights Enabled',
    category: 'App Service',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Ensures that Application Insights feature is enabled for Azure web apps.',
    more_info: 'Application insights provide advanced application monitoring. Application Insights is an extensible Application Performance Management (APM) service for developers and DevOps professionals available as monitoring feature within Azure cloud.',
    recommended_action: 'Enable Application insights for Azure Web Apps',
    link: 'https://learn.microsoft.com/en-us/azure/azure-monitor/app/app-insights-overview',
    apis: ['webApps:list', 'webApps:listAppSettings'],
    realtime_triggers: ['microsoftweb:sites:write','microsoftweb:sites:delete'],

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
                    helpers.addResult(results, 0, 'Application insights feature cannot be configured for the function App', location, webApp.id);
                    return scb();
                }

                const configs = helpers.addSource(cache, source,
                    ['webApps', 'listAppSettings', location, webApp.id]);

                if (!configs || configs.err || !configs.data) {
                    helpers.addResult(results, 3, 'Unable to query for Web App Insights: ' + helpers.addError(configs), location);
                    return scb();
                }

                if (configs.data.ApplicationInsightsAgent_EXTENSION_VERSION && configs.data.ApplicationInsightsAgent_EXTENSION_VERSION.toLowerCase() !== 'default') {
                    helpers.addResult(results, 0, 'App Insights feature is enabled for the Web App', location, webApp.id);
                } else {
                    helpers.addResult(results, 2, 'App Insights feature is disabled for the Web App', location, webApp.id);
                }

                scb();
            }, function() {
                rcb();
            });
        }, function() {
            callback(null, results, source);
        });
    }
};

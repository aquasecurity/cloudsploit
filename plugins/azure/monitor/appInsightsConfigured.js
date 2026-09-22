var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Application Insights Configured',
    category: 'Monitor',
    domain: 'Management and Governance',
    severity: 'Low',
    description: 'Ensures that Application Insights is configured for the subscription.',
    more_info: 'Application Insights collects application metrics, telemetry and trace logging data. This data supports proactive monitoring of application performance and provides the detail needed to identify the source of an incident during a reactive investigation.',
    recommended_action: 'Create an Application Insights resource and associate it with a Log Analytics workspace.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-monitor/app/app-insights-overview',
    apis: ['appInsights:list'],
    realtime_triggers: ['microsoftinsights:components:write', 'microsoftinsights:components:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.appInsights, function(location, rcb) {

            var appInsights = helpers.addSource(cache, source,
                ['appInsights', 'list', location]);

            if (!appInsights) return rcb();

            if (appInsights.err || !appInsights.data) {
                helpers.addResult(results, 3, 'Unable to query for Application Insights: ' + helpers.addError(appInsights), location);
                return rcb();
            }

            if (!appInsights.data.length) {
                helpers.addResult(results, 2, 'Application Insights is not configured for the subscription', location);
                return rcb();
            }

            helpers.addResult(results, 0, 'Application Insights is configured for the subscription', location);

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

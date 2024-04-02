var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Public Ip Address Logging Enabled',
    category: 'Log Alerts',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensures Activity Log alerts for the create/update and delete Public Ip Address events are enabled',
    more_info: 'Monitoring for Create or Update Public IP Address events gives insight into network access changes and may reduce the time it takes to detect suspicious activity.',
    recommended_action: 'Add a new log alert to the Alerts service that monitors for Public Ip Address create/update and delete events.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-monitor/platform/activity-log-alerts',
    apis: ['activityLogAlerts:listBySubscriptionId'],
    realtime_triggers: ['microsoftinsights:activitylogalerts:write', 'microsoftinsights:activitylogalerts:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.activityLogAlerts, function(location, rcb) {
            var conditionResource = 'microsoft.network/publicipaddresses';
            var text = 'Public IP Addresses';
            var activityLogAlerts = helpers.addSource(cache, source,
                ['activityLogAlerts', 'listBySubscriptionId', location]);

            helpers.checkLogAlerts(activityLogAlerts, conditionResource, text, results, location);

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

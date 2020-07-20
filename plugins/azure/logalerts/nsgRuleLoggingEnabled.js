var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Network Security Groups Rule Logging Enabled',
    category: 'Log Alerts',
    description: 'Ensures Activity Log alerts for the create or update and delete Network Security Group rule events are enabled',
    more_info: 'Monitoring for create or update and delete Network Security Group rule events gives insight into network access changes and may reduce the time it takes to detect suspicious activity.',
    recommended_action: 'Add a new log alert to the Alerts service that monitors for Network Security Group rule create or update and delete events.',
    link: 'https://docs.microsoft.com/en-us/azure/azure-monitor/platform/activity-log-alerts',
    apis: ['activityLogAlerts:listBySubscriptionId'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.activityLogAlerts, function(location, rcb) {
            var conditionResource = 'microsoft.network/networksecuritygroups/securityrules';

            var text = 'Network Security Groups rule';

            var activityLogAlerts = helpers.addSource(cache, source,
                ['activityLogAlerts', 'listBySubscriptionId', location]);

            helpers.checkLogAlerts(activityLogAlerts, conditionResource, text, results, location);

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

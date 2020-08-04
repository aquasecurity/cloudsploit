var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Policy Assignment Alerts Enabled',
    category: 'Log Alerts',
    description: 'Ensures Activity Log alerts for create or update and delete Policy Assignment events are enabled',
    more_info: 'Monitoring for create or update and delete Policy Assignment events gives insight into policy changes and may reduce the time it takes to detect suspicious activity.',
    recommended_action: 'Add a new log alert to the Alerts service that monitors for Policy Assignment create or update and delete events.',
    link: 'https://docs.microsoft.com/en-us/azure/azure-monitor/platform/activity-log-alerts',
    apis: ['activityLogAlerts:listBySubscriptionId'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.activityLogAlerts, function(location, rcb) {
            var conditionResource = 'microsoft.authorization/policyassignments';

            var text = 'Policy Assignment';

            var activityLogAlerts = helpers.addSource(cache, source,
                ['activityLogAlerts', 'listBySubscriptionId', location]);

            helpers.checkLogAlerts(activityLogAlerts, conditionResource, text, results, location);

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

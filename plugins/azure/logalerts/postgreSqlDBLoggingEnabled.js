var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'PostgreSQL Server Database Logging Enabled',
    category: 'Log Alerts',
    domain: 'Management and Governance',
    description: 'Ensures Activity Log alerts for create/update and delete PostgreSQL Server Database events are enabled.',
    more_info: 'Monitoring for create/update and delete PostgreSQL Server Database events gives insight into network access changes and may reduce the time it takes to detect suspicious activity.',
    recommended_action: 'Add a new log alert to the Alerts service that monitors for PostgreSQL Server Database create/update and delete events.',
    link: 'https://docs.microsoft.com/en-us/azure/azure-monitor/platform/activity-log-alerts',
    apis: ['activityLogAlerts:listBySubscriptionId'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.activityLogAlerts, function(location, rcb) {
            var conditionResource = 'microsoft.dbforpostgresql/servers/databases';
            var text = 'PostgreSql Server Database';
            var activityLogAlerts = helpers.addSource(cache, source,
                ['activityLogAlerts', 'listBySubscriptionId', location]);

            helpers.checkLogAlerts(activityLogAlerts, conditionResource, text, results, location);

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

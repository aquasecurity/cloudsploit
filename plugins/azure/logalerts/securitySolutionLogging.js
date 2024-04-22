const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Security Solution Logging',
    category: 'Log Alerts',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensures Activity Log Alerts for the create or update and delete Security Solution events are enabled',
    more_info: 'Monitoring for create or update and delete Security Solution events gives insight into event changes and may reduce the time it takes to detect suspicious activity.',
    recommended_action: 'Add a new log alert to the Alerts service that monitors for Security Solution create or update and delete events.',
    link: 'https://learn.microsoft.com/en-us/azure/security/azure-log-audit',
    apis: ['activityLogAlerts:listBySubscriptionId'],
    realtime_triggers: ['microsoftinsights:activitylogalerts:write', 'microsoftinsights:activitylogalerts:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.activityLogAlerts, (location, rcb) => {
            var conditionResource = 'microsoft.security/securitysolutions';

            var text = 'Security Solution';

            var activityLogAlerts = helpers.addSource(cache, source,
                ['activityLogAlerts', 'listBySubscriptionId', location]);

            helpers.checkLogAlerts(activityLogAlerts, conditionResource, text, results, location);

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};

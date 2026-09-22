var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Service Health Alert Enabled',
    category: 'Log Alerts',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensures that an activity log alert exists for Service Health events.',
    more_info: 'Service Health events cover service issues, planned maintenance and security advisories that affect the Azure services and regions in use. An activity log alert for Service Health provides visibility into these changes so that they can be acted on in time.',
    recommended_action: 'Add an activity log alert that monitors Service Health events for the subscription and sends notifications to an action group.',
    link: 'https://learn.microsoft.com/en-us/azure/service-health/alerts-activity-log-service-notifications-portal',
    apis: ['activityLogAlerts:listBySubscriptionId'],
    realtime_triggers: ['microsoftinsights:activitylogalerts:write', 'microsoftinsights:activitylogalerts:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.activityLogAlerts, function(location, rcb) {

            var activityLogAlerts = helpers.addSource(cache, source,
                ['activityLogAlerts', 'listBySubscriptionId', location]);

            if (!activityLogAlerts) return rcb();

            if (activityLogAlerts.err || !activityLogAlerts.data) {
                helpers.addResult(results, 3, 'Unable to query for Activity Alerts: ' + helpers.addError(activityLogAlerts), location);
                return rcb();
            }

            if (!activityLogAlerts.data.length) {
                helpers.addResult(results, 2, 'No existing Activity Alerts found', location);
                return rcb();
            }

            var serviceHealthAlert = activityLogAlerts.data.find(alert => alert.enabled &&
                alert.condition && alert.condition.allOf &&
                alert.condition.allOf.some(condition => condition.field &&
                    condition.field.toLowerCase() === 'category' &&
                    condition.equals && condition.equals.toLowerCase() === 'servicehealth'));

            if (serviceHealthAlert) {
                helpers.addResult(results, 0, 'Log Alert for Service Health is enabled', location, serviceHealthAlert.id);
            } else {
                helpers.addResult(results, 2, 'Log Alert for Service Health is not enabled', location);
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Policy Assignment Alerts Enabled',
    category: 'Log Alerts',
    description: 'Ensures Activity Log alerts for create or update and delete Policy Assignment events are enabled',
    more_info: 'Monitoring for create or update and delete Policy Assignment events gives insight into policy changes and may reduce the time it takes to detect suspicious activity.',
    recommended_action: 'Add a new log alert to the Alerts service that monitors for Policy Assignment create or update and delete events.',
    link: 'https://docs.microsoft.com/en-us/azure/azure-monitor/platform/activity-log-alerts',
    apis: ['resourceGroups:list','activityLogAlerts:listBySubscriptionId'],

    run: function (cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.activityLogAlerts, function (location, rcb) {

            var activityAlerts = helpers.addSource(cache, source,
                ['activityLogAlerts', 'listBySubscriptionId', location]);

            if (!activityAlerts) return rcb();

            if (activityAlerts.err || !activityAlerts.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Activity Alerts: ' + helpers.addError(activityAlerts), location);
                return rcb();
            }
            if (!activityAlerts.data.length) {
                helpers.addResult(results, 0, 'No existing Activity Alerts found', location);
                return rcb();
            }
            var writeAlertExists = false;
            var deleteAlertExists = false;
            activityAlerts.data.forEach(activityAlert => {
                let conditionList = (activityAlert &&
                    activityAlert.condition &&
                    activityAlert.condition.allOf) ?
                    activityAlert.condition.allOf : [];

                conditionList.forEach(condition => {
                    if (condition.equals &&
                        condition.equals.indexOf("Microsoft.Authorization/policyAssignments/write") > -1 &&
                        !writeAlertExists) {
                        helpers.addResult(results, 0,
                            'Log alert for Policy Assignment write exists', location, activityAlert.id);
                        writeAlertExists = true;
                    } else if (condition.equals &&
                        condition.equals.indexOf("Microsoft.Authorization/policyAssignments/delete") > -1 &&
                        !deleteAlertExists) {
                        helpers.addResult(results, 0,
                            'Log alert for Policy Assignment delete exists', location, activityAlert.id);
                        deleteAlertExists = true;
                    }
                });
            });
            if (!writeAlertExists) {
                helpers.addResult(results, 2,
                    'Log alert for Policy Assignment write does not exist', location);
            }
            if (!deleteAlertExists) {
                helpers.addResult(results, 2,
                    'Log alert for Policy Assignment delete does not exist', location);
            }

            rcb();
        }, function () {
            callback(null, results, source);
        });
    }
};

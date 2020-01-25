var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Network Security Groups Logging Enabled',
    category: 'Log Alerts',
    description: 'Ensures Activity Log alerts for the create or update and delete Network Security Group events are enabled',
    more_info: 'Monitoring for create or update and delete Network Security Group events gives insight into network access changes and may reduce the time it takes to detect suspicious activity.',
    recommended_action: 'Add a new log alert to the Alerts service that monitors for Network Security Group create or update and delete events.',
    link: 'https://docs.microsoft.com/en-us/azure/azure-monitor/platform/activity-log-alerts',
    apis: ['activityLogAlerts:listBySubscriptionId'],

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
            };

            if (!activityAlerts.data.length) {
                helpers.addResult(results, 2, 'No existing Activity Alerts found', location);
            };
            
            var deleteAlertExists = false;
            var writeAlertExists = false;
            activityAlerts.data.forEach(activityAlert => { 
                let conditionList = (activityAlert && 
                    activityAlert.condition && 
                    activityAlert.condition.allOf) ?
                    activityAlert.condition.allOf : [];

                conditionList.forEach(condition => {
                    if (condition.equals && 
                        condition.equals.indexOf('Microsoft.Network/networkSecurityGroups/write') > -1 &&
                        !writeAlertExists) {
                        helpers.addResult(results, 0, 
                            'Log alert for Network Security Groups write is enabled', location, activityAlert.id);
                        writeAlertExists = true;
                    } else if (condition.equals &&
                        condition.equals.indexOf("microsoft.network/networksecuritygroups/delete") > -1 &&
                        !deleteAlertExists) {
                        helpers.addResult(results, 0, 
                            'Log alert for Network Security Groups delete is enabled', location, activityAlert.id);
                        deleteAlertExists = true;
                    };
                });
            });
            
            if (!writeAlertExists) {
                helpers.addResult(results, 2, 
                    'Log alert for Network Security Groups write does not exist', location);
            };

            if (!deleteAlertExists) {
                helpers.addResult(results, 2, 
                    'Log Alert for Network Security Groups delete does not exist', location);
            };
            
            rcb();
        }, function () {
            callback(null, results, source);
        });
    }
};

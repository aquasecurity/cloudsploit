var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Network Security Groups Logging Enabled',
    category: 'Log Alerts',
    description: 'Ensure an Activity Log Alert for the Create or Update and Delete Network Security Group Rule event is enabled.',
    more_info: 'Monitoring for Create or Update and Delete Network Security Group events gives insight into network access changes and may reduce the time it takes to detect suspicious activity.',
    recommended_action: '1. Enter the Alerts service. 2. Select the Add Activity Log Alert button at the top of the page. 3. In Criteria, Select Security in the Event Category and Create or Update Network Security groups next to Operation Name, then add Delete Network Security Groups logging.',
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
                    'Unable to query Activity Alerts: ' + helpers.addError(activityAlerts), location);
                return rcb();
            };

            if (!activityAlerts.data.length) {
                helpers.addResult(results, 1, 'No existing Activity Alerts', location);
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
                            'Log Alert for Writing to Network Security Groups is enabled', location, activityAlert.id);
                        writeAlertExists = true;
                    } else if (condition.equals &&
                        condition.equals.indexOf("microsoft.network/networksecuritygroups/delete") > -1 &&
                        !deleteAlertExists) {
                        helpers.addResult(results, 0, 
                            'Log Alert for Deleting Network Security Groups is enabled', location, activityAlert.id);
                        deleteAlertExists = true;
                    };
                });
            });
            
            if (!writeAlertExists) {
                helpers.addResult(results, 1, 
                    'Log Alert for Writing to Network Security Groups does not exist', location);
            };

            if (!deleteAlertExists) {
                helpers.addResult(results, 1, 
                    'Log Alert for Deleting Network Security Groups does not exist', location);
            };
            
            rcb();
        }, function () {
            callback(null, results, source);
        });
    }
};

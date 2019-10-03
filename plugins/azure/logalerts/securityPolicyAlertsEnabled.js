var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Security Policy Alerts Enabled',
    category: 'Log Alerts',
    description: 'Ensure an Activity Log Alert for the Create or Update Security Policy Rule event is enabled.',
    more_info: 'Monitoring for Create or Update Network Security Group events gives insight into network access changes and may reduce the time it takes to detect suspicious activity.',
    recommended_action: '1. Enter the Alerts service. 2. Select the Add Activity Log Alert button at the top of the page. 3. In Criteria, Select Security in the Event Category and Create or Update Security Policy next to Operation Name',
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
                    'Unable to query Activity Alerts: ' + helpers.addError(activityAlerts), location);
                return rcb();
            }
            if (!activityAlerts.data.length) {
                helpers.addResult(results, 1, 'No existing Activity Alerts', location);
            }
            var alertExists = false;
            activityAlerts.data.forEach(activityAlert => {                
                let conditionList = (activityAlert && 
                    activityAlert.condition && 
                    activityAlert.condition.allOf) ?
                    activityAlert.condition.allOf : [];

                conditionList.forEach(condition => {
                    if (condition.equals && 
                        condition.equals.indexOf("microsoft.security/policies/write") > -1 &&
                        !alertExists) {
                        helpers.addResult(results, 0, 
                            'Write alert for Security Policy exists', location, activityAlert.id);
                        alertExists = true;
                    };
                });
            });
            if (!alertExists) {
                helpers.addResult(results, 1, 
                    'Write alert for Security Policy does not exist', location);
            };
            
            rcb();
        }, function () {
            callback(null, results, source);
        });
    }
};

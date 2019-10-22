var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Security Policy Alerts Enabled',
    category: 'Log Alerts',
    description: 'Ensures Activity Log alerts for create or update Security Policy Rule events are enabled',
    more_info: 'Monitoring for create or update Security Policy Rule events gives insight into policy changes and may reduce the time it takes to detect suspicious activity.',
    recommended_action: 'Add a new log alert to the Alerts service that monitors for Security Policy Rule create or update events.',
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
                helpers.addResult(results, 2, 'No existing Activity Alerts found', location);
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
                            'Log alert for Security Policy write exists', location, activityAlert.id);
                        alertExists = true;
                    };
                });
            });
            if (!alertExists) {
                helpers.addResult(results, 2, 
                    'Log alert for Security Policy write does not exist', location);
            };
            
            rcb();
        }, function () {
            callback(null, results, source);
        });
    }
};

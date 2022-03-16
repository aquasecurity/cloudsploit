var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Virtual Machine Power Off Alert Enabled',
    category: 'Log Alerts',
    domain: 'Management and Governance',
    description: 'Ensures Activity Log alerts for the power off Virtual Machine events are enabled',
    more_info: 'Monitoring for power off Virtual Machine events gives insight into network access changes and may reduce the time it takes to detect suspicious activity.',
    recommended_action: 'Add a new log alert to the Alerts service that monitors for Virtual Machine power off events.',
    link: 'https://docs.microsoft.com/en-us/azure/azure-monitor/platform/activity-log-alerts',
    apis: ['activityLogAlerts:listBySubscriptionId'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.activityLogAlerts, function(location, rcb) {
            var conditionResource = 'microsoft.compute/virtualmachines';
            var text = 'Virtual Machines';
            var activityLogAlerts = helpers.addSource(cache, source,
                ['activityLogAlerts', 'listBySubscriptionId', location]);

            if (!activityLogAlerts) return rcb();

            if (activityLogAlerts.err || !activityLogAlerts.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Activity Alerts: ' + helpers.addError(activityLogAlerts), location);
                return rcb();
            }

            if (!activityLogAlerts.data.length) {
                helpers.addResult(results, 2, 'No existing Activity Alerts found', location);
                return rcb();
            }

            let alertPowerOffEnabled = false;
            let subscriptionId;

            for (let res in activityLogAlerts.data) {
                const activityLogAlertResource = activityLogAlerts.data[res];
                subscriptionId = '/subscriptions/' + activityLogAlertResource.id.split('/')[2];

                if (activityLogAlertResource.type &&
                    activityLogAlertResource.type.toLowerCase() !== 'Microsoft.Insights/ActivityLogAlerts'.toLowerCase()) continue;

                const allConditions = activityLogAlertResource.condition;

                if (!allConditions || !allConditions.allOf || !allConditions.allOf.length) continue;

                var conditionOperation = allConditions.allOf.filter((d) => {
                    return (d.equals && d.equals.toLowerCase().indexOf(conditionResource) > -1);
                });
                if (conditionOperation && conditionOperation.length) {
                    allConditions.allOf.forEach(condition => {
                        if (condition.equals && condition.equals.toLowerCase() && condition.equals.toLowerCase().indexOf(conditionResource + '/poweroff') > -1) {
                            alertPowerOffEnabled = (!alertPowerOffEnabled && activityLogAlertResource.enabled ? true : alertPowerOffEnabled);
                        }
                    });
                }
            }

            if (!alertPowerOffEnabled) {
                helpers.addResult(results, 2,
                    `Log alert for ${text} powerOff is not enabled`, location, subscriptionId);
            } else {
                helpers.addResult(results, 0,
                    `Log alert for ${text} powerOff is enabled`, location, subscriptionId);
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

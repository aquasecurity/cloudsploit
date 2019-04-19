const async = require('async');

const helpers = require('../../../helpers/azure');


module.exports = {
    title: 'Virtual Network Alerts Monitor',
    category: 'Activity Log Alerts',
    description: 'Triggers alerts when Virtual Networks are created or modified.',
    more_info: 'Monitoring Virtual Network events gives insight into network access changes and may reduce the risk of breaches due to malicious configuration alteration.',
    recommended_action: 'Configure Virtual Networks to limit access exclusively to those resources that need it. Create activity log alerts to monitor changes to your Virtual Networks configuration.',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-network/security-overview, https://docs.microsoft.com/en-us/azure/azure-monitor/platform/alerts-activity-log',
    apis: ['resourceGroups:list','activityLogAlerts:listByResourceGroup','resources:list'],

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        function networkResourceExists(resourceList){
            return JSON.stringify(resourceList).indexOf('Microsoft.Network') > -1
        }

        async.each(locations.activityLogAlerts, function(location, rcb){
            const activityLogAlerts = helpers.addSource(
                cache, source, ['activityLogAlerts', 'listByResourceGroup', location]
            );

            var resourceList = helpers.addSource(cache, source, ['resources', 'list', location]);

            if(networkResourceExists(resourceList)){
                if (!activityLogAlerts) return rcb();

                if (activityLogAlerts.err) {
                    helpers.addResult(results, 3, 'Unable to query activity log alerts: ' + helpers.addError(activityLogAlerts), location);
                    return rcb();
                }
                if (!activityLogAlerts.data || !activityLogAlerts.data.length) {
                    helpers.addResult(results, 2, 'Activity log alerts are not setup for this location', location);
                } else {
                    let alertCreateUpdateExists = false;
                    let alertCreateUpdateEnabled = false;
                    let alertDeleteExists = false;
                    let alertDeleteEnabled = false;

                    for (let res in activityLogAlerts.data) {
                        const activityLogAlertResource = activityLogAlerts.data[res];
                        if (activityLogAlertResource.error == true) {
                            continue;
                        }

                        for (let alert in activityLogAlertResource) {
                            const activityLogAlert = activityLogAlertResource[alert];
                            if (activityLogAlert.type !== 'Microsoft.Insights/ActivityLogAlerts') continue;
                            const allConditions = activityLogAlert.condition;

                            for (let conres in allConditions.allOf) {
                                const condition = allConditions.allOf[conres].equals;
                                if (condition.indexOf("Microsoft.Network/virtualNetworks/write") > -1) {
                                    alertCreateUpdateExists = true;
                                    alertCreateUpdateEnabled = (!alertCreateUpdateEnabled && activityLogAlertResource.enabled ? true : alertCreateUpdateEnabled);
                                } else if (condition.indexOf("Microsoft.Network/virtualNetworks/delete") > -1) {
                                    alertDeleteExists = true;
                                    alertDeleteEnabled = (!alertDeleteEnabled && activityLogAlertResource.enabled ? true : alertDeleteEnabled);
                                }
                            }
                        }

                        if (alertCreateUpdateExists && alertCreateUpdateEnabled &&
                            alertDeleteExists && alertDeleteEnabled) {
                            helpers.addResult(
                                results,
                                0,
                                'Virtual Network events are being monitored for Create/Update and Delete events',
                                location
                            );
                        } else {
                            if ((!alertCreateUpdateExists) ||
                                (alertCreateUpdateExists && !alertCreateUpdateEnabled)) {
                                helpers.addResult(
                                    results,
                                    2,
                                    'Virtual Network events are not being monitored for Create/Update events',
                                    location
                                );
                            } else {
                                helpers.addResult(
                                    results,
                                    0,
                                    'Virtual Network events are being monitored for Create/Update events',
                                    location
                                );
                            }

                            if ((!alertDeleteExists) ||
                                (alertDeleteExists && !alertDeleteEnabled)) {
                                helpers.addResult(
                                    results,
                                    2,
                                    'Virtual Network events are not being monitored for Delete events',
                                    location
                                );
                            } else {
                                helpers.addResult(
                                    results,
                                    0,
                                    'Virtual Network events are being monitored for Delete events',
                                    location
                                );
                            }
                        }

                        if (!alertCreateUpdateExists &&
                            !alertDeleteExists) {
                            helpers.addResult(
                                results,
                                2,
                                'Activity log alerts are not setup for Virtual Network events',
                                location
                            );
                        }
                    }
                }
            } else {
                helpers.addResult(
                    results,
                    0,
                    'No matching resources found, ignoring monitoring requirement',
                    location
                );
            }

            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};

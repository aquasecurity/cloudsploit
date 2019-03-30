const async = require('async');

const helpers = require('../../../helpers/azure');


module.exports = {
    title: 'SQL Server Firewall Rule Alerts Monitor',
    category: 'Activity Log Alerts',
    description: 'Triggers alerts when SQL Server Firewall Rules are created or modified.',
    more_info: 'Monitoring SQL Server Firewall Rule events gives insight into network access changes and may reduce the risk of data breaches due to malicious alteration to firewall configuration.',
    recommended_action: 'Configure SQL Server Firewall rules to limit access exclusively to those resources that need it. Create activity log alerts to monitor changes to your SQL Server security configuration.',
    link: 'https://docs.microsoft.com/en-us/azure/sql-database/sql-database-firewall-configure, https://docs.microsoft.com/en-us/azure/azure-monitor/platform/alerts-activity-log',
    apis: ['resourceGroups:list','activityLogAlerts:listByResourceGroup','resources:list'],

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        function sqlResourceExists(resourceList){
            return JSON.stringify(resourceList).indexOf('Microsoft.Sql') > -1
        }

        async.each(locations.activityLogAlerts, function(location, rcb){
            const activityLogAlerts = helpers.addSource(
                cache, source, ['activityLogAlerts', 'listByResourceGroup', location]
            );

            var resourceList = helpers.addSource(cache, source, ['resources', 'list', location]);

            if(sqlResourceExists(resourceList)){
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
                        const allConditions = activityLogAlertResource.condition;

                        for (let conres in allConditions.allOf) {
                            const condition = allConditions.allOf[conres].equals;
                            if (condition.indexOf("Microsoft.Sql/servers/firewallRules/write") > -1) {
                                alertCreateUpdateExists = true;
                                alertCreateUpdateEnabled = (!alertCreateUpdateEnabled && activityLogAlertResource.enabled ? true : alertCreateUpdateEnabled);
                            } else if (condition.indexOf("Microsoft.Sql/servers/firewallRules/delete") > -1) {
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
                            'SQL Server Firewall Rule events are being monitored for Create/Update and Delete events',
                            location
                        );
                    } else {
                        if ((!alertCreateUpdateExists) ||
                            (alertCreateUpdateExists && !alertCreateUpdateEnabled)) {
                            helpers.addResult(
                                results,
                                2,
                                'SQL Server Firewall Rule events are not being monitored for Create/Update events',
                                location
                            );
                        } else {
                            helpers.addResult(
                                results,
                                0,
                                'SQL Server Firewall Rule events are being monitored for Create/Update events',
                                location
                            );
                        }

                        if ((!alertDeleteExists) ||
                            (alertDeleteExists && !alertDeleteEnabled)) {
                            helpers.addResult(
                                results,
                                2,
                                'SQL Server Firewall Rule events are not being monitored for Delete events',
                                location
                            );
                        } else {
                            helpers.addResult(
                                results,
                                0,
                                'SQL Server Firewall Rule events are being monitored for Delete events',
                                location
                            );
                        }
                    }

                    if (!alertCreateUpdateExists &&
                        !alertDeleteExists) {
                        helpers.addResult(
                            results,
                            2,
                            'Activity log alerts are not setup for SQL Server firewall rule events',
                            location
                        );
                    }
                }
            } else {
                helpers.addResult(
                    results,
                    0,
                    'No SQL Server Resources found, ignoring monitoring requirement',
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

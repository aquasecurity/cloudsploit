const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'SQL Server Firewall Rule Alerts Monitor',
    category: 'Log Alerts',
    description: 'Ensures Activity Log Alerts for the create or update and delete SQL Server Firewall Rules events are enabled',
    more_info: 'Monitoring for create or update and delete SQL Server Firewall Rules events gives insight into event changes and may reduce the time it takes to detect suspicious activity.',
    recommended_action: 'Add a new log alert to the Alerts service that monitors for SQL Server Firewall Rules create or update and delete events.',
    link: 'https://docs.microsoft.com/en-us/azure/sql-database/sql-database-firewall-configure',
    apis: ['resourceGroups:list', 'activityLogAlerts:listByResourceGroup', 'resources:list'],
    compliance: {
        hipaa: 'HIPAA requires the auditing of changes to access controls for network ' +
                'resources.',
        pci: 'PCI requires the use of firewalls to protect cardholder data. Configuring ' +
                'a monitor for SQL Server firewall rules ensures the integrity of those ' +
                'firewalls.'
    },

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        const activityLogAlerts = helpers.addSource(
            cache, source, ['activityLogAlerts', 'listByResourceGroup', 'global']
        );

        if (!activityLogAlerts) return callback();

        if (activityLogAlerts.err || !activityLogAlerts.data) {
            helpers.addResult(results, 3,
                'Unable to query for Log Alerts: ' + helpers.addError(activityLogAlerts), 'global');
            return callback();
        }

        if (!activityLogAlerts.data.length) {
            helpers.addResult(results, 2,
                'No existing Log Alerts found', 'global');

            return callback();
        }

        async.each(locations.resources, function(location, rcb) {

            var resourceList = helpers.addSource(cache, source, ['resources', 'list', location]);

            if (!resourceList || resourceList.err || !resourceList.data) {
                helpers.addResult(results, 3,
                    'Unable to obtain resource list data: ' + helpers.addError(resourceList),
                    location
                );
                return rcb();
            }

            var sqlServerResourceList = resourceList.data.filter((d) => {
                return  d.type == 'Microsoft.Sql/servers';
            });

            if (sqlServerResourceList &&
                sqlServerResourceList.length &&
                sqlServerResourceList.length>0) {

                let alertCreateUpdateExists = false;
                let alertCreateUpdateEnabled = false;
                let alertDeleteExists = false;
                let alertDeleteEnabled = false;

                for (let res in activityLogAlerts.data) {
                    const activityLogAlertResource = activityLogAlerts.data[res];

                    if (activityLogAlertResource.type !== 'Microsoft.Insights/ActivityLogAlerts') continue;

                    const allConditions = activityLogAlertResource.condition;

                    var conditionOperation = allConditions.allOf.filter((d) => {
                        return d.field == 'operationName';
                    });

                    if (conditionOperation && conditionOperation.length) {
                        for (c in conditionOperation) {
                            var condition = conditionOperation[c];
                            if (condition.equals.indexOf("Microsoft.Sql/servers/firewallRules/write") > -1) {
                                alertCreateUpdateExists = true;
                                alertCreateUpdateEnabled = (!alertCreateUpdateEnabled && activityLogAlertResource.enabled ? true : alertCreateUpdateEnabled);
                            } else if (condition.equals.indexOf("Microsoft.Sql/servers/firewallRules/delete") > -1) {
                                alertDeleteExists = true;
                                alertDeleteEnabled = (!alertDeleteEnabled && activityLogAlertResource.enabled ? true : alertDeleteEnabled);
                            }
                        }
                    }
                }

                if (alertCreateUpdateExists &&
                    alertCreateUpdateEnabled &&
                    alertDeleteExists &&
                    alertDeleteEnabled) {
                    helpers.addResult(
                        results,
                        0,
                        'Log Alert for SQL Server Firewall Rule write and delete is enabled',
                        location
                    );
                } else {
                    if ((!alertCreateUpdateExists) ||
                        (alertCreateUpdateExists &&
                            !alertCreateUpdateEnabled)) {
                        helpers.addResult(results, 2,
                            'Log Alert for SQL Server Firewall Rule write and delete is not enabled',
                            location
                        );
                    } else {
                        helpers.addResult(results, 0,
                            'Log Alert for SQL Server Firewall Rule write is enabled',
                            location
                        );
                    }

                    if ((!alertDeleteExists) ||
                        (alertDeleteExists &&
                            !alertDeleteEnabled)) {
                        helpers.addResult(results, 2,
                            'Log Alert for SQL Server Firewall Rule delete is not enabled',
                            location
                        );
                    } else {
                        helpers.addResult(results, 0,
                            'Log Alert for SQL Server Firewall Rule delete is enabled',
                            location
                        );
                    }
                }

                if (!alertCreateUpdateExists &&
                    !alertDeleteExists) {
                    helpers.addResult(results, 2,
                        'Log Alert for SQL Server Firewall Rule is not enabled',
                        location
                    );
                }

            } else {
                helpers.addResult(results, 0,
                    'No SQL Server resources found',
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

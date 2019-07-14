const async = require('async');

const helpers = require('../../../helpers/azure');


module.exports = {
    title: 'Virtual Network Alerts Monitor',
    category: 'Log Alerts',
    description: 'Triggers alerts when Virtual Networks are created or modified.',
    more_info: 'Monitoring Virtual Network events gives insight into network access changes and may reduce the risk of breaches due to malicious configuration alteration.',
    recommended_action: 'Configure Virtual Networks to limit access exclusively to those resources that need it. Create activity log alerts to monitor changes to your Virtual Networks configuration.',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-network/security-overview',
    apis: ['resourceGroups:list','activityLogAlerts:listByResourceGroup','resources:list'],
    compliance: {
        hipaa: 'HIPAA requires the auditing of changes to access controls for network ' +
                'resources.',
        pci: 'PCI requires the use of firewalls to protect cardholder data. Configuring ' +
                'a monitor for changes to Virtual Networks ensures the integrity of those ' +
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

        if (activityLogAlerts.err) {
            helpers.addResult(results, 3,
                'Unable to query activity log alerts: ' + helpers.addError(activityLogAlerts), 'global');
            return callback();
        }

        if (!activityLogAlerts.data || !activityLogAlerts.data.length) {
            helpers.addResult(results, 2,
                'Activity log alerts are not setup', 'global');
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

            var virtualNetworkResourceList = resourceList.data.filter((d) => {
                return d.type == 'Microsoft.Network/virtualNetworks';
            });

            if (virtualNetworkResourceList &&
                virtualNetworkResourceList.length &&
                virtualNetworkResourceList.length>0) {

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
                            if (condition.equals.indexOf("Microsoft.Network/virtualNetworks/write") > -1) {
                                alertCreateUpdateExists = true;
                                alertCreateUpdateEnabled = (!alertCreateUpdateEnabled && activityLogAlertResource.enabled ? true : alertCreateUpdateEnabled);
                            } else if (condition.equals.indexOf("Microsoft.Network/virtualNetworks/delete") > -1) {
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
                        'Virtual Network events are being monitored for Create/Update and Delete events',
                        location
                    );
                } else {
                    if ((!alertCreateUpdateExists) ||
                        (alertCreateUpdateExists &&
                            !alertCreateUpdateEnabled)) {
                        helpers.addResult(results, 2,
                            'Virtual Network events are not being monitored for Create/Update events',
                            location
                        );
                    } else {
                        helpers.addResult(results, 0,
                            'Virtual Network events are being monitored for Create/Update events',
                            location
                        );
                    }

                    if ((!alertDeleteExists) ||
                        (alertDeleteExists &&
                            !alertDeleteEnabled)) {
                        helpers.addResult(results, 2,
                            'Virtual Network events are not being monitored for Delete events',
                            location
                        );
                    } else {
                        helpers.addResult(results, 0,
                            'Virtual Network events are being monitored for Delete events',
                            location
                        );
                    }
                }

                if (!alertCreateUpdateExists &&
                    !alertDeleteExists) {
                    helpers.addResult(results, 2,
                        'Activity log alerts are not setup for Virtual Network events',
                        location
                    );
                }

            } else {
                helpers.addResult(results, 0,
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

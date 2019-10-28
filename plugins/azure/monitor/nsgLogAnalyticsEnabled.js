const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'NSG Log Analytics Enabled',
    category: 'Monitor',
    description: 'Ensures Network Security Group logs are sent to the Log Analytics workspace',
    more_info: 'Enabling Log Analytics for Network Security Groups ensures that logs are shipped to a central repository that can be queried and audited.',
    recommended_action: 'Enable sending of logs to Log Analytics for each Network Security Group resource in the Azure Monitor.',
    link: 'https://docs.microsoft.com/en-us/azure/azure-monitor/platform/collect-activity-logs',
    apis: ['networkSecurityGroups:listAll', 'diagnosticSettingsOperations:nsg:list'],
    compliance: {
        pci: 'PCI requires monitoring and logging of all network traffic. ' +
            'These include malicious attempts to access services within the ' +
            'infrastructure.',
        hipaa: 'HIPAA requires monitoring and logging of all network traffic. ' +
            'These include malicious attempts to access services within the ' +
            'infrastructure.'
    },


    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.diagnosticSettingsOperations.nsg, (location, rcb) => {

            const diagnosticSettingsResources = helpers.addSource(cache, source,
                ['diagnosticSettingsOperations', 'nsg', 'list', location]);

            if (!diagnosticSettingsResources) return rcb();

            if (diagnosticSettingsResources.err || !diagnosticSettingsResources.data) {
                helpers.addResult(results, 3,
                    'Unable to query Diagnostic Settings: ' + helpers.addError(diagnosticSettingsResources), location);
                return rcb();
            }

            if (!diagnosticSettingsResources.data.length) {
                helpers.addResult(results, 0, 'No Network Security Groups found', location);
                return rcb();
            }

            diagnosticSettingsResources.data.forEach(networkGroupSettings => {
                var isWorkspace = networkGroupSettings.value.filter((d) => {
                    return d.hasOwnProperty('workspaceId') == true;
                });

                if (!networkGroupSettings.value.length) {
                    helpers.addResult(results, 2,
                        'Diagnostic Settings are not configured for the Network Security Group', location, networkGroupSettings.id);
                } else {
                    if (isWorkspace.length) {
                        helpers.addResult(results, 0,
                            'Send to Log Analytics is configured for the Network Security Group', location, networkGroupSettings.id);
                    } else {
                        helpers.addResult(results, 2,
                            'Send to Log Analytics is not configured for the Network Security Group', location, networkGroupSettings.id);
                    }
                }
            });

            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};

const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'NSG Log Analytics Enabled',
    category: 'Monitor',
    description: 'Ensures Network Security Group logs are sent to the Log Analytics workspace',
    more_info: 'Enabling Log Analytics for Network Security Groups ensures that logs are shipped to a central repository that can be queried and audited.',
    recommended_action: 'Enable sending of logs to Log Analytics for each Network Security Group resource in the Azure Monitor.',
    link: 'https://docs.microsoft.com/en-us/azure/azure-monitor/platform/collect-activity-logs',
    apis: ['networkSecurityGroups:listAll', 'diagnosticSettings:listByNetworkSecurityGroup'],
    compliance: {
        pci: 'PCI requires monitoring and logging of all network traffic. ' +
            'These include malicious attempts to access services within the ' +
            'infrastructure.',
        hipaa: 'HIPAA requires monitoring and logging of all network traffic. ' +
            'These include malicious attempts to access services within the ' +
            'infrastructure.'
    },

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.networkSecurityGroups, (location, rcb) => {
            const networkSecurityGroups = helpers.addSource(cache, source,
                ['networkSecurityGroups', 'listAll', location]);

            if (!networkSecurityGroups) return rcb();

            if (networkSecurityGroups.err || !networkSecurityGroups.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Network Security Groups: ' + helpers.addError(networkSecurityGroups), location);
                return rcb();
            }

            if (!networkSecurityGroups.data.length) {
                helpers.addResult(results, 0, 'No existing Network Security Groups found', location);
                return rcb();
            }

            networkSecurityGroups.data.forEach(function(nsg) {
                const diagnosticSettings = helpers.addSource(cache, source,
                    ['diagnosticSettings', 'listByNetworkSecurityGroup', location, nsg.id]);

                if (!diagnosticSettings || diagnosticSettings.err || !diagnosticSettings.data) {
                    helpers.addResult(results, 3,
                        'Unable to query diagnostics settings: ' + helpers.addError(diagnosticSettings), location, nsg.id);
                } else if (!diagnosticSettings.data.length) {
                    helpers.addResult(results, 2, 'No existing diagnostics settings', location, nsg.id);
                } else {
                    var found = false;
                    diagnosticSettings.data.forEach(function(ds) {
                        if (ds.logs && ds.logs.length) found = true;
                    });

                    if (found) {
                        helpers.addResult(results, 0, 'NSG Log Analytics is enabled for NSG', location, nsg.id);
                    } else {
                        helpers.addResult(results, 2, 'NSG Log Analytics is not enabled for NSG', location, nsg.id);
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'NSG Log Analytics Enabled',
    category: 'Monitor',
    description: 'Ensures Network Security Groups logs are sent to the Log Analytics workspace.',
    more_info: 'Enabling Log Analytics ensures that logs are shipped to a central repository that can be queried and audited, following cloud security best practices.',
    recommended_action: '1. Go to Azure Monitor. 2. Select Diagnostic setting from the settings tab on the list to the left. 3. Choose the resource. 4. If no diagnostic setting defined, add diagnostic setting and enable Send to Log Analytics, if diagnostic setting are defined, edit the setting to enable Send to Log Analytics.',
    link: 'https://docs.microsoft.com/en-us/azure/azure-monitor/platform/collect-activity-logs',
    apis: ['networkSecurityGroups:listAll', 'diagnosticSettingsOperations:nsg:list'],

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.diagnosticSettingsOperations.nsg, (location, rcb) => {

            const diagnosticSettingsResources = helpers.addSource(cache, source,
                ['diagnosticSettingsOperations', 'nsg', 'list', location]);

            if (!diagnosticSettingsResources) return rcb();

            if (diagnosticSettingsResources.err) {
                helpers.addResult(results, 3,
                    'Unable to query Diagnostic Settings: ' + helpers.addError(diagnosticSettingsResources), location);
                return rcb();
            };

            if (!diagnosticSettingsResources.data || !diagnosticSettingsResources.data.length) {
                helpers.addResult(results, 0, 'No Network Security Groups', location);
                return rcb();
            };

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
                        helpers.addResult(results, 1,
                            'Send to Log Analytics is not configured for the Network Security Group', location, networkGroupSettings.id);
                    };
                };
            });

            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};

const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Key Vault Log Analytics Enabled',
    category: 'Monitor',
    description: 'Ensures Key Vault Log Analytics logs are being properly delivered to Azure Monitor',
    more_info: 'Enabling Send to Log Analytics ensures that all Key Vault logs are being properly monitored and managed.',
    recommended_action: 'Send all diagnostic logs for Key Vault from the Azure Monitor service to Log Analytics.',
    link: 'https://docs.microsoft.com/en-us/azure/azure-monitor/platform/collect-activity-logs',
    apis: ['vaults:list', 'diagnosticSettingsOperations:kv:list'],
    compliance: {
        hipaa: 'HIPAA requires that a secure audit record for ' +
                'write read and delete is created for all ' +
                'activities in the system.'
    },

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.diagnosticSettingsOperations.kv, (location, rcb) => {

            const diagnosticSettingsResources = helpers.addSource(cache, source, 
                ['diagnosticSettingsOperations', 'kv', 'list', location]);

            if (!diagnosticSettingsResources) return rcb();

            if (diagnosticSettingsResources.err || !diagnosticSettingsResources.data) {
                helpers.addResult(results, 3,
                    'Unable to query Diagnostic Settings: ' + helpers.addError(diagnosticSettingsResources),location);
                return rcb();
            }

            if (!diagnosticSettingsResources.data.length) {
                helpers.addResult(results, 0, 'No Key Vaults found', location);
                return rcb();
            }

            diagnosticSettingsResources.data.forEach(keyVaultSettings => {
                var isWorkspace = keyVaultSettings.value.filter((d) => {
                    return d.hasOwnProperty('workspaceId') == true;
                });
                
                if (!keyVaultSettings.value.length) {
                    helpers.addResult(results, 2,
                        'Diagnostic Settings are not configured for the Key Vault', location, keyVaultSettings.id);
                } else {
                    if (isWorkspace.length) {
                        helpers.addResult(results, 0,
                            'Send to Log Analytics is configured for the Key Vault', location, keyVaultSettings.id);
                    } else {
                        helpers.addResult(results, 2,
                            'Send to Log Analytics is not configured for the Key Vault', location, keyVaultSettings.id);
                    }
                };
            });
            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};

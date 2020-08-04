const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Key Vault Log Analytics Enabled',
    category: 'Monitor',
    description: 'Ensures Key Vault Log Analytics logs are being properly delivered to Azure Monitor',
    more_info: 'Enabling Send to Log Analytics ensures that all Key Vault logs are being properly monitored and managed.',
    recommended_action: 'Send all diagnostic logs for Key Vault from the Azure Monitor service to Log Analytics.',
    link: 'https://docs.microsoft.com/en-us/azure/azure-monitor/platform/collect-activity-logs',
    apis: ['vaults:list', 'diagnosticSettings:listByKeyVault'],
    compliance: {
        hipaa: 'HIPAA requires that a secure audit record for ' +
                'write read and delete is created for all ' +
                'activities in the system.'
    },

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.vaults, (location, rcb) => {
            const vaults = helpers.addSource(cache, source,
                ['vaults', 'list', location]);

            if (!vaults) return rcb();

            if (vaults.err || !vaults.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Key Vaults: ' + helpers.addError(vaults), location);
                return rcb();
            }

            if (!vaults.data.length) {
                helpers.addResult(results, 0, 'No existing Key Vaults found', location);
                return rcb();
            }

            vaults.data.forEach(function(vault) {
                const diagnosticSettings = helpers.addSource(cache, source,
                    ['diagnosticSettings', 'listByKeyVault', location, vault.id]);

                if (!diagnosticSettings || diagnosticSettings.err || !diagnosticSettings.data) {
                    helpers.addResult(results, 3,
                        'Unable to query diagnostics settings: ' + helpers.addError(diagnosticSettings), location, vault.id);
                } else if (!diagnosticSettings.data.length) {
                    helpers.addResult(results, 2, 'No existing diagnostics settings', location, vault.id);
                } else {
                    var found = false;
                    diagnosticSettings.data.forEach(function(ds) {
                        if (ds.logs && ds.logs.length) found = true;
                    });

                    if (found) {
                        helpers.addResult(results, 0, 'Key vault analytics is enabled for vault', location, vault.id);
                    } else {
                        helpers.addResult(results, 2, 'Key vault analytics is not enabled for vault', location, vault.id);
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

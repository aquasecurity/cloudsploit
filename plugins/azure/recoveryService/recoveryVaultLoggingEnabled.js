const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Recovery Services Vault Logging Enabled',
    category: 'Recovery Service Vault',
    domain: 'Backup',
    severity: 'Medium',
    description: 'Ensure that Azure Recovery Services Vaults have diagnostic logs enabled.',
    more_info: 'Diagnostic logs provide valuable insights into the operation and health of the Recovery Services Vault. By enabling diagnostic logs, you can monitor and analysis the insights which can be used for alerting and reporting.',
    recommended_action: 'Modify the Recovery Service vault and enable diagnostic logs.',
    link: 'https://learn.microsoft.com/en-us/azure/backup/backup-azure-diagnostic-events?tabs=recovery-services-vaults',
    apis: ['diagnosticSettings:listByRecoveryServiceVault', 'recoveryServiceVaults:listBySubscriptionId'],
    realtime_triggers: ['microsoftrecoveryservices:vaults:write', 'microsoftrecoveryservices:vaults:delete', 'microsoftinsights:diagnosticsettings:write', 'microsoftinsights:diagnosticsettings:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.recoveryServiceVaults, (location, rcb) => {
            const serviceVaults = helpers.addSource(cache, source,
                ['recoveryServiceVaults', 'listBySubscriptionId', location]);

            if (!serviceVaults) return rcb();

            if (serviceVaults.err || !serviceVaults.data) {
                helpers.addResult(results, 3,
                    'Unable to list Recovery Service Vaults: ' + helpers.addError(serviceVaults), location);
                return rcb();
            }

            if (!serviceVaults.data.length) {
                helpers.addResult(results, 0, 'No Recovery Service Vaults found', location);
                return rcb();
            }

            for (let vault of serviceVaults.data) {
                if (!vault.id) continue;

                const diagnosticSettings = helpers.addSource(cache, source, 
                    ['diagnosticSettings', 'listByRecoveryServiceVault', location, vault.id]);

                if (!diagnosticSettings || !diagnosticSettings.data || diagnosticSettings.err) {
                    helpers.addResult(results, 3,
                        'Unable to query for Recovery Service Vault diagnostic settings: ' + helpers.addError(diagnosticSettings), location, vault.id);
                    continue;
                }

                var found = diagnosticSettings.data.find(ds => ds.logs && ds.logs.length);

                if (found) {
                    helpers.addResult(results, 0, 'Recovery Service Vault has diagnostic logs enabled', location, vault.id);
                } else {
                    helpers.addResult(results, 2, 'Recovery Service Vault does not have diagnostic logs enabled', location, vault.id);
                }
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};

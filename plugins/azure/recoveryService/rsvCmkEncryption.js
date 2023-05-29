const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Recovery Service Vault CMK Encryption',
    category: 'Recovery Service Vault',
    domain: 'Backup',
    description: 'Ensure that Microsoft Azure Recovery Service Vault have CMK Encryption Enabled.',
    more_info: 'A customer-managed key gives you the ownership to bring your own key in Azure Key Vault. When you enable a customer-managed key, you can manage its rotations, control the access and permissions to use it, and audit its use.',
    recommended_action: 'Modify Recovery Service vault\'s encryption settings and enable CMK encryption.',
    link: 'https://learn.microsoft.com/en-us/azure/backup/encryption-at-rest-with-cmk',
    apis: ['recoveryServiceVaults:getRecoveryServiceVault', 'recoveryServiceVaults:listBySubscriptionId'],

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
                    'Unable to query for list Recovery Service vaults: ' + helpers.addError(serviceVaults), location);
                return rcb();
            }

            if (!serviceVaults.data.length) {
                helpers.addResult(results, 0, 'No Recovery Service Vaults found', location);
                return rcb();
            }

            for (let vault of serviceVaults.data) {
                if (!vault.id) continue;

                const getVault = helpers.addSource(cache, source, 
                    ['recoveryServiceVaults', 'getRecoveryServiceVault', location, vault.id]);

                if (!getVault.data || getVault.err) {
                    helpers.addResult(results, 3,
                        'Unable to query for get Recovery Service Vault: ' + helpers.addError(getVault), location);
                    continue;
                }
                
                if (getVault.data.encryption && getVault.data.encryption.keyVaultProperties &&
                getVault.data.encryption.keyVaultProperties.keyUri) {
                    helpers.addResult(results, 0, 'Recovery Service Vault has CMK encryption enabled', location, getVault.id);
                } else {
                    helpers.addResult(results, 2, 'Recovery Service Vault does not have CMK encryption enabled', location);
                }

            }
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
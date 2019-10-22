const async = require('async');
const helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Key Vault Recovery Enabled',
    category: 'Key Vault',
    description: 'Ensures that Purge Protection and Soft Delete are enabled on all Key Vaults.',
    more_info: 'Purge Protection and Soft Delete are features that safeguard losing key access. With these setting enabled, key vaults have recovery actions available to restore deleted or compromised key vaults.',
    recommended_action: "1. Login to the Azure CLI. 2. Use the command and change *vaultname* to the vault to enable Soft Delete: 'az resource update --id $(az keyvault show --name *vaultname* -o tsv | awk '{print $1}') --set properties.enableSoftDelete=true'. 3. Use the command and change *vaultname* to the vault to enable Surge Protection: 'az resource update --id $(az keyvault show --name *vaultname* -o tsv | awk '{print $1}') --set properties.enablePurgeProtection=true'",
    link: 'https://docs.microsoft.com/en-us/azure/key-vault/key-vault-ovw-soft-delete',
    apis: ['resourceGroups:list', 'vaults:listByResourceGroup', 'vaults:get'],

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.vaults, function (location, rcb) {
            const vaults = helpers.addSource(cache, source,
                ['vaults', 'get', location]);

            if (!vaults) return rcb();

            if (vaults.err || !vaults.data) {
                helpers.addResult(results, 3,
                'Unable to query Key Vaults: ' + helpers.addError(vaults), location);
                return rcb();
            };

            if (!vaults.data.length) {
                helpers.addResult(results, 0, 'No existing Key Vaults', location);
            };
            
            vaults.data.forEach(vault => {
                let vaultProperties = vault.properties;

                if (vaultProperties &&
                    vaultProperties.enablePurgeProtection) {
                    helpers.addResult(results, 0, 
                        'Purge protection is enabled for the vault', location, vault.id);
                } else { 
                    helpers.addResult(results, 1, 
                        'Purge protection is disabled for the vault', location, vault.id);
                };

                if (vaultProperties &&
                    vaultProperties.enableSoftDelete) {
                    helpers.addResult(results, 0, 
                        'Soft delete is enabled for the vault', location, vault.id);
                } else {
                    helpers.addResult(results, 2, 
                        'Soft delete is disabled for the vault', location, vault.id);
                };
            });
            
            rcb();
        }, function () {
        // Global checking goes here
            callback(null, results, source);
        });
    }
};

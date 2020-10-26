const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Key Vault Recovery Enabled',
    category: 'Key Vaults',
    description: 'Ensures that Purge Protection and Soft Delete are enabled on all Key Vaults',
    more_info: 'Purge Protection and Soft Delete are features that safeguard losing key access. With these setting enabled, key vaults have recovery actions available to restore deleted or compromised key vaults.',
    recommended_action: 'Once Key Vaults are created, the Azure CLI must be used to update the vault Soft Delete and Purge Protection settings.',
    link: 'https://docs.microsoft.com/en-us/azure/key-vault/key-vault-ovw-soft-delete',
    apis: ['vaults:list'],
    compliance: {
        hipaa: 'HIPAA requires that all encryption mechanisms be protected against ' +
                'modifications or loss.'
    },

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.vaults, function(location, rcb) {
            var vaults = helpers.addSource(cache, source,
                ['vaults', 'list', location]);

            if (!vaults) return rcb();

            if (vaults.err || !vaults.data) {
                helpers.addResult(results, 3, 'Unable to query for Key Vaults: ' + helpers.addError(vaults), location);
                return rcb();
            }

            if (!vaults.data.length) {
                helpers.addResult(results, 0, 'No Key Vaults found', location);
                return rcb();
            }

            vaults.data.forEach(function(vault) {
                if (vault.enablePurgeProtection && vault.enableSoftDelete) {
                    helpers.addResult(results, 0,
                        'Purge protection and soft delete are enabled for the Key Vault', location, vault.id);
                } else {
                    let msg = [
                        `Purge protection is ${vault.enablePurgeProtection ? '' : 'not'} enabled.`,
                        `Soft delete is ${vault.enableSoftDelete ? '' : 'not'} enabled.`
                    ];
                    helpers.addResult(results, 2, msg.join(' '), location, vault.id);
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};

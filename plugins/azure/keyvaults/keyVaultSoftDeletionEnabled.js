var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Key Vault Soft Deletion',
    category: 'Key Vaults',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Ensure that Azure Key Vault soft delete feature is enabled.',
    more_info: 'Key Vault\'s soft-delete feature allows recovery of the deleted vaults and deleted key vault objects.',
    recommended_action: 'Enable soft delete',
    link: 'https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview',
    apis: ['vaults:list'],
    realtime_triggers: ['microsoftkeyvault:vaults:write', 'microsoftkeyvault:vaults:delete'],
    settings: {
        deletion_retentions_in_days: {
            name: 'Keep Deleted Key Vaults for Days',
            description: 'Number of days that a key vault is marked for deletion persists until it is permanently deleted',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: '90'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        const config = {
            keepForDays: parseInt(settings.deletion_retentions_in_days || this.settings.deletion_retentions_in_days.default)
        };

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

            for (let vault of vaults.data) {
                if (vault.enableSoftDelete && vault.softDeleteRetentionInDays){
                    const retentionDays = vault.softDeleteRetentionInDays;
                    if (retentionDays >= config.keepForDays) {
                        helpers.addResult(results, 0, `Key vault deletion policy is configured to persist deleted vaults for ${retentionDays} of ${config.keepForDays} days desired limit`, location, vault.id);
                    } else {
                        helpers.addResult(results, 2, `Key vault deletion policy is configured to persist deleted vaults for ${retentionDays} of ${config.keepForDays} days desired limit`, location, vault.id);
                    }
                } else {
                    helpers.addResult(results, 2, 'Key Vault does not have soft deletion enabled', location, vault.id);
                } 
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
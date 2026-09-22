var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Key Vault RBAC Enabled',
    category: 'Key Vaults',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Ensures that Azure Role-Based Access Control is enabled for Key Vaults.',
    more_info: 'Azure RBAC provides fine-grained access management of keys, secrets and certificates in a Key Vault, and allows permissions to be managed in one place across all key vaults. Vault access policies, the alternative, offer coarser control and cannot be centrally audited in the same way.',
    recommended_action: 'Enable Azure role-based access control from the access configuration settings of the Key Vault.',
    link: 'https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide',
    apis: ['vaults:list'],
    realtime_triggers: ['microsoftkeyvault:vaults:write', 'microsoftkeyvault:vaults:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.vaults, function(location, rcb) {
            var vaults = helpers.addSource(cache, source,
                ['vaults', 'list', location]);

            if (!vaults) return rcb();

            if (vaults.err || !vaults.data) {
                helpers.addResult(results, 3, 'Unable to query for Key Vaults: ' + helpers.addError(vaults), location);
                return rcb();
            }

            if (!vaults.data.length) {
                helpers.addResult(results, 0, 'No existing Key Vaults found', location);
                return rcb();
            }

            for (let vault of vaults.data) {
                if (!vault.id) continue;

                if (vault.enableRbacAuthorization) {
                    helpers.addResult(results, 0, 'Key Vault has RBAC authorization enabled', location, vault.id);
                } else {
                    helpers.addResult(results, 2, 'Key Vault does not have RBAC authorization enabled', location, vault.id);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Key Vault Key Rotation Enabled',
    category: 'Key Vaults',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Ensures that automatic key rotation is enabled for Key Vault keys.',
    more_info: 'A key rotation policy generates a new key version automatically at a configured frequency. Rotating keys without manual intervention reduces the risk of a key being used beyond its recommended cryptoperiod.',
    recommended_action: 'Configure a rotation policy with a rotate action for each key from the Key Vault key rotation policy settings.',
    link: 'https://learn.microsoft.com/en-us/azure/key-vault/keys/how-to-configure-key-rotation',
    apis: ['vaults:list', 'vaults:listKeys', 'getKey:get'],
    realtime_triggers: ['microsoftkeyvault:vaults:write', 'microsoftkeyvault:vaults:delete', 'microsoftkeyvault:vaults:keys:write', 'microsoftkeyvault:vaults:keys:delete'],

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

            vaults.data.forEach(function(vault) {
                var keys = helpers.addSource(cache, source,
                    ['vaults', 'listKeys', location, vault.id]);

                if (!keys || keys.err || !keys.data) {
                    helpers.addResult(results, 3, 'Unable to query for Key Vault keys: ' + helpers.addError(keys), location, vault.id);
                    return;
                }

                if (!keys.data.length) {
                    helpers.addResult(results, 0, 'No existing Key Vault keys found', location, vault.id);
                    return;
                }

                keys.data.forEach(function(key) {
                    if (!key.id) return;

                    var keyData = helpers.addSource(cache, source,
                        ['getKey', 'get', location, key.id]);

                    if (!keyData || keyData.err || !keyData.data) {
                        helpers.addResult(results, 3, 'Unable to query for Key Vault key: ' + helpers.addError(keyData), location, key.id);
                        return;
                    }

                    var rotationPolicy = keyData.data.rotationPolicy;

                    var rotationEnabled = rotationPolicy && rotationPolicy.lifetimeActions &&
                        rotationPolicy.lifetimeActions.some(lifetimeAction => lifetimeAction.action &&
                            lifetimeAction.action.type && lifetimeAction.action.type.toLowerCase() === 'rotate' &&
                            lifetimeAction.trigger && (lifetimeAction.trigger.timeAfterCreate || lifetimeAction.trigger.timeBeforeExpiry));

                    if (rotationEnabled) {
                        helpers.addResult(results, 0, 'Key Vault key has automatic rotation enabled', location, key.id);
                    } else {
                        helpers.addResult(results, 2, 'Key Vault key does not have automatic rotation enabled', location, key.id);
                    }
                });
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

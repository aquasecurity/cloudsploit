var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Key Vault Key Expiry RBAC',
    category: 'Key Vaults',
    domain: 'Application Integration',
    severity: 'High',
    description: 'Ensures that expiration date is set for all keys in RBAC-enabled Key Vaults.',
    more_info: 'Setting an expiration date on keys helps in key lifecycle management and ensures that keys are rotated regularly.',
    recommended_action: 'Modify keys in RBAC-enabled Key Vaults to have an expiration date set.',
    link: 'https://learn.microsoft.com/en-us/azure/key-vault/about-keys-secrets-and-certificates',
    apis: ['vaults:list', 'vaults:getKeys'],
    settings: {
        key_vault_key_expiry_fail: {
            name: 'Key Vault Key Expiry Fail',
            description: 'Return a failing result when key expiration date is within this number of days in the future',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: '30'
        }
    },
    realtime_triggers: ['microsoftkeyvault:vaults:write', 'microsoftkeyvault:vaults:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);
        var config = {
            key_vault_key_expiry_fail: parseInt(settings.key_vault_key_expiry_fail || this.settings.key_vault_key_expiry_fail.default)
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

            vaults.data.forEach(function(vault) {
                if (!vault || !vault.properties) {
                    helpers.addResult(results, 3, 'Unable to read vault properties', location, vault.id);
                    return;
                }
                if (!vault.properties.enableRbacAuthorization) {
                    return;
                }

                var keys = helpers.addSource(cache, source,
                    ['vaults', 'getKeys', location, vault.id]);

                if (!keys || keys.err || !keys.data) {
                    helpers.addResult(results, 3, 'Unable to query for Key Vault keys: ' + helpers.addError(keys), location, vault.id);
                } else if (!keys.data.length) {
                    helpers.addResult(results, 0, 'No Key Vault keys found', location, vault.id);
                } else {
                    keys.data.forEach(function(key) {
                        var keyName = key.kid.substring(key.kid.lastIndexOf('/') + 1);
                        var keyId = `${vault.id}/keys/${keyName}`;

                        if (!key.attributes || !key.attributes.enabled) {
                            helpers.addResult(results, 0,
                                'Key is not enabled', location, keyId);
                        } else if (key.attributes && (key.attributes.expires || key.attributes.exp)) {
                            let keyExpiry = key.attributes.exp ? key.attributes.exp * 1000 : key.attributes.expires;
                            let difference = Math.round((new Date(keyExpiry).getTime() - (new Date).getTime())/(24*60*60*1000));
                            if (difference > config.key_vault_key_expiry_fail) {
                                helpers.addResult(results, 0,
                                    `Key expires in ${difference} days`, location, keyId);
                            } else if (difference > 0){
                                helpers.addResult(results, 2,
                                    `Key expires in ${difference} days`, location, keyId);
                            } else {
                                helpers.addResult(results, 2,
                                    `Key expired ${Math.abs(difference)} days ago`, location, keyId);
                            }
                        } else {
                            helpers.addResult(results, 0,
                                'Key expiration is not enabled', location, keyId);
                        }
                    });
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Key Expiration Enabled',
    category: 'Key Vaults',
    domain: 'Identity and Access Management',
    description: 'Ensure that all Keys in Azure Key Vault have an expiry time set.',
    more_info: 'Setting an expiry time on all keys forces key rotation and removes unused and forgotten keys from being used.',
    recommended_action: 'Ensure each Key Vault has an expiry time set that provides for sufficient rotation.',
    link: 'https://docs.microsoft.com/en-us/azure/key-vault/about-keys-secrets-and-certificates',
    apis: ['vaults:list', 'vaults:getKeys'],
    settings: {
        encryption_keys_expiry_period: {
            name: 'Key Vault Keys Expiration Period',
            description: 'The period of time in days for a key expiration.',
            regex: '^(?:36[0-5]|3[0-5][0-9]|[12][0-9][0-9]|[1-9][0-9]|[1-9])$',
            default: 30
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);
        var encryption_keys_expiry_period = parseInt(settings.encryption_keys_expiry_period || this.settings.encryption_keys_expiry_period.default); 

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

            vaults.data.forEach(function(vault){
                var keys = helpers.addSource(cache, source,
                    ['vaults', 'getKeys', location, vault.id]);

                if (!keys || keys.err || !keys.data) {
                    helpers.addResult(results, 3, 'Unable to query for Key Vault keys: ' + helpers.addError(keys), location, vault.id);
                } else if (!keys.data.length) {
                    helpers.addResult(results, 0, 'No Key Vault keys found', location, vault.id);
                } else {
                    keys.data.forEach(function(key){
                        var keyName = key.kid.substring(key.kid.lastIndexOf('/') + 1);
                        var keyId = `${vault.id}/keys/${keyName}`;
                        
                        if (key.attributes) {
                            let expiryPeriodInDays = helpers.daysBetween(new Date(), key.attributes.expires);
                            if (expiryPeriodInDays < encryption_keys_expiry_period) {
                                helpers.addResult(results, 0,
                                    'Key Vault encryption keys expiration is within the set expiry period', location, keyId);
                            } else {
                                helpers.addResult(results, 2,
                                    'Key Vault encryption keys expiration greater then the set expiry period', location, keyId);
                            }
                        } else {
                            helpers.addResult(results, 2,
                                'Key Vault encryption keys expiration is not enabled', location, keyId);
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

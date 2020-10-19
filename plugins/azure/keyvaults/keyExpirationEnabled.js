var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Key Expiration Enabled',
    category: 'Key Vaults',
    description: 'Ensure that all Keys in Azure Key Vault have an expiry time set.',
    more_info: 'Setting an expiry time on all keys forces key rotation and removes unused and forgotten keys from being used.',
    recommended_action: 'Ensure each Key Vault has an expiry time set that provides for sufficient rotation.',
    link: 'https://docs.microsoft.com/en-us/azure/key-vault/about-keys-secrets-and-certificates',
    apis: ['vaults:list', 'vaults:getKeys'],
    compliance: {
        pci: 'PCI has strict requirements regarding the use of encryption keys ' +
            'to protect cardholder data. These requirements include rotating ' +
            'the Key periodically. Key Vaults provides Key expiration capabilities that ' +
            'should be enabled.'
    },
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
                            let attributes = key.attributes;
                            if ((attributes.expires && attributes.expires !== null && attributes.expires !== '') || (attributes.exp && attributes.exp !== null && attributes.exp !== '')) {
                                helpers.addResult(results, 0,
                                    'Expiry date is set for the key', location, keyId);
                            } else {
                                helpers.addResult(results, 2,
                                    'Expiry date is not set for the key', location, keyId);
                            }
                        } else {
                            helpers.addResult(results, 2,
                                'Expiry date is not set for the key', location, keyId);
                        }
                    });
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};

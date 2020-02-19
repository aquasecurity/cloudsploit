var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Key Expiration Enabled',
    category: 'Key Vaults',
    description: 'Ensure that all Keys in Azure Key Vault have an expiry time set.',
    more_info: 'Setting an expiry time on all keys forces key rotation and removes unused and forgotten keys from being used.',
    recommended_action: 'Ensure each Key Vault has an expiry time set that provides for sufficient rotation.',
    link: 'https://docs.microsoft.com/en-us/azure/key-vault/about-keys-secrets-and-certificates',
    apis: ['vaults:list', 'KeyVaultClient:getKeys'],
    compliance: {
        pci: 'PCI has strict requirements regarding the use of encryption keys ' +
            'to protect cardholder data. These requirements include rotating ' +
            'the Key periodically. Key Vaults provides Key expiration capabilities that ' +
            'should be enabled.'
    },
    run: function (cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.KeyVaultClient, function (location, rcb) {

            var keys = helpers.addSource(cache, source, 
                ['KeyVaultClient', 'getKeys', location]);

            if (!keys) return rcb();

            if (keys.err || !keys.data) {
                helpers.addResult(results, 3, 'Unable to query for Keys: ' + helpers.addError(keys), location);
                return rcb();
            }

            if (!keys.data.length) {
                helpers.addResult(results, 0, 'No Keys found', location);
                return rcb();
            }
            
            keys.data.forEach(key => {
                if (key.attributes) {
                    let attributes = key.attributes;
                    if (attributes.expires && attributes.expires !== null && attributes.expires !== "") {
                        helpers.addResult(results, 0,
                            'Expiry date is set for the key', location, key.kid);
                    } else {
                        helpers.addResult(results, 2, 
                            'Expiry date is not set for the key', location, key.kid);
                    }
                } else {
                    helpers.addResult(results, 2, 
                        'Expiry date is not set for the key', location, key.kid);
                }
            });
            
            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
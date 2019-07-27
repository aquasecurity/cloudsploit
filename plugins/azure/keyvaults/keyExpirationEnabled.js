var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Key Expiration Enabled',
    category: 'Key Vault',
    description: 'Ensure that all Keys in Azure Key Vault have an expiry time set.',
    more_info: 'Setting an expiry time on all keys forces key rotation and removes unused and forgotten keys from being used.',
    recommended_action: '1. Go to Key vaults. 2. For each Key vault, click on Keys. 3. Ensure that each key in the vault has EXPIRATION DATE set as appropriate.',
    link: 'https://docs.microsoft.com/en-us/azure/key-vault/about-keys-secrets-and-certificates',
    apis: ['vaults:list', 'KeyVaultClient:getKeys'],

    run: function (cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.KeyVaultClient, function (location, rcb) {

            var keys = helpers.addSource(cache, source, 
                ['KeyVaultClient', 'getKeys', location]);

            if (!keys) return rcb();

            if (keys.err || !keys.data) {
                helpers.addResult(results, 3, 
                    'Unable to query Keys: ' + helpers.addError(keys), location);
                return rcb();
            };

            if (!keys.data.length) {
                helpers.addResult(results, 0, 'No Keys found', location);
            };
            
            keys.data.forEach(key => {
                if (key.attributes) {
                    let attributes = key.attributes;
                    if (attributes.expires && attributes.expires !== null && attributes.expires !== "") {
                        helpers.addResult(results, 0,
                            'Expiry date is set for the key', location, key.kid);
                    } else {
                        helpers.addResult(results, 2, 
                            'Expiry date is not set for the key', location, key.kid);
                    };
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
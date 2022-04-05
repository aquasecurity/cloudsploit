var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'CMK Creation for App Tier Enabled',
    category: 'Key Vaults',
    domain: 'Identity and Access Management',
    description: 'Ensure that a Customer-Managed Key (CMK) is created and configured for your Microsoft Azure application tier.',
    more_info: 'Setting a CMK for app tier, you gain full control over who can use this key to access the application data, implementing the principle of least privilege on the encryption key ownership and usage.',
    recommended_action: 'Ensure each Key Vault has an expiry time set that provides for sufficient rotation.',
    link: 'https://docs.microsoft.com/en-us/azure/azure-app-configuration/concept-customer-managed-keys',
    apis: ['vaults:list', 'vaults:getKeys'],

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

            vaults.data.forEach((vault) => {
                var keys = helpers.addSource(cache, source,
                    ['vaults', 'getKeys', location, vault.id]);

                if (!keys || keys.err || !keys.data) {
                    helpers.addResult(results, 3, 'Unable to query for Key Vault keys: ' + helpers.addError(keys), location, vault.id);
                } else if (!keys.data.length) {
                    helpers.addResult(results, 0, 'No Key Vault keys found', location, vault.id);
                } else {
                    keys.data.forEach((key) => {
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
            callback(null, results, source);
        });
    }
};

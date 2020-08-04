var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Secret Expiration Enabled',
    category: 'Key Vaults',
    description: 'Ensures that all secrets in Azure Key Vault have an expiry time set.',
    more_info: 'Setting an expiry time on all secrets forces secret rotation and removes unused and forgotten secrets from being used.',
    recommended_action: 'Ensure each Key Vault has an expiry time set that provides for sufficient rotation.',
    link: 'https://docs.microsoft.com/en-us/azure/secret-vault/about-secrets-secrets-and-certificates',
    apis: ['vaults:list', 'vaults:getSecrets'],

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

            vaults.data.forEach(function(vault) {
                var secrets = helpers.addSource(cache, source,
                    ['vaults', 'getSecrets', location, vault.id]);

                if (!secrets || secrets.err || !secrets.data) {
                    helpers.addResult(results, 3, 'Unable to query for Key Vault secrets: ' + helpers.addError(secrets), location, vault.id);
                } else if (!secrets.data.length) {
                    helpers.addResult(results, 0, 'No Key Vault secrets found', location, vault.id);
                } else {
                    secrets.data.forEach(function(secret) {
                        var secretName = secret.id.substring(secret.id.lastIndexOf('/') + 1);
                        var secretId = `${vault.id}/secrets/${secretName}`;

                        if (secret.attributes) {
                            let attributes = secret.attributes;
                            if (!attributes.enabled) {
                                helpers.addResult(results, 0,
                                    'The secret is disabled', location, secretId);
                            } else if (attributes.exp && attributes.exp !== null && attributes.exp !== '') {
                                helpers.addResult(results, 0,
                                    'Expiry date is set for the secret', location, secretId);
                            } else {
                                helpers.addResult(results, 2,
                                    'Expiry date is not set for the secret', location, secretId);
                            }
                        } else {
                            helpers.addResult(results, 2,
                                'Expiry date is not set for the secret', location, secretId);
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
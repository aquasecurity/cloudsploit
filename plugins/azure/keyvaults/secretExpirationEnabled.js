var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Secret Expiration Enabled',
    category: 'Key Vaults',
    description: 'Ensures that all secrets in Azure Key Vault have an expiry time set.',
    more_info: 'Setting an expiry time on all secrets forces secret rotation and removes unused and forgotten secrets from being used.',
    recommended_action: 'Ensure each Key Vault has an expiry time set that provides for sufficient rotation.',
    link: 'https://docs.microsoft.com/en-us/azure/secret-vault/about-secrets-secrets-and-certificates',
    apis: ['vaults:list', 'KeyVaultClient:getSecrets'],

    run: function (cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.KeyVaultClient, function (location, rcb) {

            var secrets = helpers.addSource(cache, source,
                ['KeyVaultClient', 'getSecrets', location]);

            if (!secrets) return rcb();

            if (secrets.err || !secrets.data) {
                helpers.addResult(results, 3, 'Unable to query for secrets: ' + helpers.addError(secrets), location);
                return rcb();
            }

            if (!secrets.data.length) {
                helpers.addResult(results, 0, 'No secrets found', location);
                return rcb();
            }

            secrets.data.forEach(secret => {
                if (secret.attributes) {
                    let attributes = secret.attributes;
                    if (attributes.enabled &&
                        attributes.expires &&
                        attributes.expires !== null && attributes.expires !== "") {
                        helpers.addResult(results, 0,
                            'Expiry date is set for the secret', location, secret.id);
                    } else if (!attributes.enabled) {
                        helpers.addResult(results, 0,
                            'The secret is disabled', location, secret.id);
                    } else {
                        helpers.addResult(results, 2,
                            'Expiry date is not set for the secret', location, secret.id);
                    }
                } else {
                    helpers.addResult(results, 2,
                        'Expiry date is not set for the secret', location, secret.kid);
                }
            });

            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Key Vault In Use',
    category: 'Key Vaults',
    domain: 'Application Integration',
    description: 'Ensures that Key Vaults are being used to store secrets.',
    more_info: 'App secrets control access to the application and thus need to be secured externally to the app configuration, storing the secrets externally and referencing them in the configuration also enables key rotation without having to redeploy the app service.',
    recommended_action: 'Ensure that Azure Key Vaults are being used to store secrets.',
    link: 'https://docs.microsoft.com/en-us/azure/app-service/app-service-key-vault-references',
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
                helpers.addResult(results, 2, 'Key Vaults are not being used to store secrets', location);
                return rcb();
            }

            let keyVaultsBeingUsed = false;
            for (let vault of vaults.data) {
                var keys = helpers.addSource(cache, source,
                    ['vaults', 'getKeys', location, vault.id]);

                var secrets = helpers.addSource(cache, source,
                    ['vaults', 'getSecrets', location, vault.id]);

                if (!keys || keys.err || !keys.data) {
                    helpers.addResult(results, 3, 'Unable to query for Key Vault keys: ' + helpers.addError(keys), location, vault.id);
                } else if (keys.data.length) {
                    keyVaultsBeingUsed = true;
                    break;
                }

                if (!secrets || secrets.err || !secrets.data) {
                    helpers.addResult(results, 3, 'Unable to query for Key Vault secrets: ' + helpers.addError(secrets), location, vault.id);
                } else if (secrets.data.length) {
                    keyVaultsBeingUsed = true;
                    break;
                }
            }

            if (keyVaultsBeingUsed) {
                helpers.addResult(results, 0, 'Key Vaults are being used to store secrets', location);
            } else {
                helpers.addResult(results, 2, 'Key Vaults are not being used to store secrets', location);
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Key Vault Secret Expiry RBAC',
    category: 'Key Vaults',
    domain: 'Application Integration',
    severity: 'High',
    description: 'Proactively check for Key Vault secrets expiry date and rotate them before expiry date is reached.',
    more_info: 'After the expiry date has reached for Key Vault secret, it cannot be used for storing sensitive and confidential data such as passwords and database connection strings anymore.',
    recommended_action: 'Ensure that Key Vault secrets are rotated before they get expired.',
    link: 'https://learn.microsoft.com/en-us/azure/secret-vault/about-secrets-secrets-and-certificates',
    apis: ['vaults:list', 'vaults:getSecrets'],
    settings: {
        key_vault_secret_expiry_fail: {
            name: 'Key Vault Secret Expiry Fail',
            description: 'Return a failing result when secret expiration date is within this number of days in the future',
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
            key_vault_secret_expiry_fail: parseInt(settings.key_vault_secret_expiry_fail || this.settings.key_vault_secret_expiry_fail.default)
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
                // Check if vault is RBAC-enabled
                if (!vault.properties || !vault.properties.enableRbacAuthorization) {
                    helpers.addResult(results, 0,
                        'Key Vault is not RBAC-enabled', location, vault.id);
                    return;
                }

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

                        if (!secret.attributes || !secret.attributes.enabled) {
                            helpers.addResult(results, 0, 'Secret is not enabled', location, secretId);
                        } else if (secret.attributes && (secret.attributes.exp || secret.attributes.expiry)) {
                            let attributes = secret.attributes;
                            let secretExpiry = attributes.exp ? attributes.exp * 1000 : attributes.expiry;
                            let difference = Math.round((new Date(secretExpiry).getTime() - (new Date).getTime())/(24*60*60*1000));
                            if (difference > config.key_vault_secret_expiry_fail) {
                                helpers.addResult(results, 0,
                                    `Secret expires in ${difference} days`, location, secretId);
                            } else if (difference > 0){
                                helpers.addResult(results, 2,
                                    `Secret expires in ${difference} days`, location, secretId);
                            } else {
                                helpers.addResult(results, 2,
                                    `Secret expired ${Math.abs(difference)} days ago`, location, secretId);
                            }
                        } else {
                            helpers.addResult(results, 0,
                                'Secret expiration is not enabled', location, secretId);
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

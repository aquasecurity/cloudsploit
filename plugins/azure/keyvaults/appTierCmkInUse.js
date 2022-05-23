var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'App Tier CMK In Use',
    category: 'Key Vaults',
    domain: 'Application Integration',
    description: 'Ensure that a Customer-Managed Key (CMK) is created and configured for your Microsoft Azure application tier.',
    more_info: 'Setting a CMK for app tier, you gain full control over who can use this key to access the application data, implementing the principle of least privilege on the encryption key ownership and usage.',
    recommended_action: 'Ensure a CMK created and configured for application tier in each region.',
    link: 'https://docs.microsoft.com/en-us/azure/azure-app-configuration/concept-customer-managed-keys',
    apis: ['vaults:list', 'vaults:getKeys'],
    settings: {
        app_tier_tag_key: {
            name: 'App-Tier Tag Key',
            description: 'Tag key to indicate App-Tier Key Vault keys',
            regex: '^.*$s',
            default: ''
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);
        var config = {
            app_tier_tag_key: settings.app_tier_tag_key || this.settings.app_tier_tag_key.default
        };

        if (!config.app_tier_tag_key.length) return callback(null, results, source);

        async.each(locations.vaults, function(location, rcb) {
            var vaults = helpers.addSource(cache, source,
                ['vaults', 'list', location]);

            if (!vaults) return rcb();

            if (vaults.err || !vaults.data) {
                helpers.addResult(results, 3, 'Unable to query for Key Vaults: ' + helpers.addError(vaults), location);
                return rcb();
            }

            if (!vaults.data.length) {
                helpers.addResult(results, 2, 'No Key Vaults found', location);
                return rcb();
            }

            let appTierKey;
            vaults.data.forEach((vault) => {
                var keys = helpers.addSource(cache, source,
                    ['vaults', 'getKeys', location, vault.id]);

                if (!keys || keys.err || !keys.data) {
                    helpers.addResult(results, 3, 'Unable to query for Key Vault keys: ' + helpers.addError(keys), location, vault.id);
                    return;
                }

                if (keys.data.length) {
                    for (let key of keys.data) {
                        var keyName = key.kid.substring(key.kid.lastIndexOf('/') + 1);
                        var keyId = `${vault.id}/keys/${keyName}`;
                        if (key.tags) {
                            if (Object.keys(key.tags).includes(config.app_tier_tag_key)) {
                                appTierKey = keyId;
                                break;
                            }
                        }
                    }
                }
            });

            if (appTierKey) {
                helpers.addResult(results, 0, `CMK exists for application tier: ${appTierKey}`, location);
            } else {
                helpers.addResult(results, 2, 'CMK does not exist for application tier', location);
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

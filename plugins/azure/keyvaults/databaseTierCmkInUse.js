var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Database Tier CMK In Use',
    category: 'Key Vaults',
    domain: 'Application Integration',
    severity: 'High',
    description: 'Ensure that a Customer-Managed Key (CMK) is created and configured for your Microsoft Azure application tier.',
    more_info: 'Setting a CMK for database tier, you gain full control over who can use this key to access the database tier data, implementing the principle of least privilege on the encryption key ownership and usage.',
    recommended_action: 'Ensure a CMK created and configured for database tier in each region.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-sql/database/transparent-data-encryption-byok-overview?view=azuresql',
    apis: ['vaults:list', 'vaults:getKeys'],
    settings: {
        db_tier_tag_key: {
            name: 'Database-Tier Tag Key',
            description: 'Tag key to indicate Database-Tier Key Vault keys',
            regex: '^.*$s',
            default: ''
        }
    },
    realtime_triggers: ['microsoftkeyvault:vaults:write', 'microsoftkeyvault:vaults:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);
        var config = {
            db_tier_tag_key: settings.db_tier_tag_key || this.settings.db_tier_tag_key.default
        };

        if (!config.db_tier_tag_key.length) return callback(null, results, source);

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

            let dbTierKey;
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
                            if (Object.keys(key.tags).includes(config.db_tier_tag_key)) {
                                dbTierKey = keyId;
                                break;
                            }
                        }
                    }
                }
            });

            if (dbTierKey) {
                helpers.addResult(results, 0, `CMK exists for database tier: ${dbTierKey}`, location);
            } else {
                helpers.addResult(results, 2, 'CMK does not exist for database tier', location);
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

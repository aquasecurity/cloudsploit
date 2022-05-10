var async = require('async');
var helpers = require('../../../helpers/azure');
var _ = require('underscore');

module.exports = {
    title: 'CMK Creation for Database Tier Enabled',
    category: 'Key Vaults',
    domain: 'Identity and Access Management',
    description: 'Ensures that a Customer-Managed Key (CMK) is created and configured for your Microsoft Azure database tier.',
    more_info: 'Setting a CMK for database tier, you gain full control over who can use this key to access the database tier data, implementing the principle of least privilege on the encryption key ownership and usage.',
    recommended_action: 'Ensure each Key Vault has a CMK created and configured for database tier.',
    link: 'https://docs.microsoft.com/en-us/azure/azure-sql/database/transparent-data-encryption-byok-overview?view=azuresql',
    apis: ['vaults:list', 'vaults:getKeys'],
    settings: {
        database_tier_tag_sets: {
            name: 'Database Tier Tag Sets',
            description: 'An object of allowed tag set key value pairs to use for the CMKs creation for Database Tier',
            // eslint-disable-next-line no-useless-escape
            regex: '/("?)\b(\w+)\1\s*:\s*("?)((?:\w+[-+*%])*?\w+)\b\3/g',
            default: {}
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);
        var config = {
            database_tier_tag_sets: settings.database_tier_tag_sets || this.settings.database_tier_tag_sets.default
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

                        if (key.tags) {
                            const tags = key.tags;
                            const allowedTagSets = config.database_tier_tag_sets;
                            const result = _.pick(tags, (v, k) => _.isEqual(allowedTagSets[k], v));

                            if (Object.entries(result).length) {
                                helpers.addResult(results, 0,
                                    'CMK Creation for Database Tier is enabled', location, keyId);
                            } else {
                                helpers.addResult(results, 2,
                                    'CMK Creation for Database Tier is disabled', location, keyId);
                            }
                        } else {
                            helpers.addResult(results, 2,
                                'CMK Creation for Database Tier is disabled', location, keyId);
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

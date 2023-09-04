var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'User API Keys Rotated',
    category: 'Identity',
    domain: 'Identity and Access Management',
    description: 'Ensure that user API keys are rotated regularly in order to reduce accidental exposures.',
    more_info: 'User API keys should be rotated frequently to avoid having them accidentally exposed.',
    link: 'https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingcredentials.htm',
    recommended_action: 'Rotate user API keys after regular intervals',
    apis: ['user:list', 'apiKey:list'],
    settings: {
        api_keys_rotated_fail: {
            name: 'Auth Tokens Rotated Fail',
            description: 'Return a failing result when API keys exceed this number of days without being rotated',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: '90'
        }
    },

    run: function (cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.objectFirstKey(cache['regionSubscription']['list']);

        var config = {
            api_keys_rotated_fail: parseInt(settings.api_keys_rotated_fail || this.settings.api_keys_rotated_fail.default)
        }

        var users = helpers.addSource(cache, source,
            ['user', 'list', region]);

        var apiKeys = helpers.addSource(cache, source,
            ['apiKey', 'list', region]);

        if (!users || !apiKeys) return callback(null, results, source);

        if (users.err || !users.data) {
            helpers.addResult(results, 3,
                'Unable to query for users: ' + helpers.addError(users), 'global');
            return callback(null, results, source);
        }

        if (apiKeys.err || !apiKeys.data) {
            helpers.addResult(results, 3,
                'Unable to query user API keys: ' + helpers.addError(apiKeys), 'global');
            return callback(null, results, source);
        }

        if (!apiKeys.data.length) {
            helpers.addResult(results, 0, 'No user API keys found', 'global');
            return callback(null, results, source);
        }

        for (let key of apiKeys.data) {
            if (!key.keyId) continue;

            let timeCreated = key.timeCreated ? key.timeCreated : new Date();
            let difference = helpers.daysBetween(timeCreated, new Date());

            if (difference > config.api_keys_rotated_fail) {
                helpers.addResult(results, 2, `API key is ${difference} days old`, 'global', key.id);
            } else {
                helpers.addResult(results, 0, `API key is ${difference} days old`, 'global', key.id);
            }
        }

        callback(null, results, source);
    }
};

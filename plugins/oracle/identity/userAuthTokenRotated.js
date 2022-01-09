var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'User Auth Token Rotated',
    category: 'Identity',
    domain: 'Identity and Access Management',
    description: 'Ensure that user auth tokens are rotated regularly in order to reduce accidental exposures.',
    more_info: 'User auth tokens should be rotated frequently to avoid having them accidentally exposed.',
    link: 'https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingcredentials.htm',
    recommended_action: 'Rotate user auth tokens after regular intervals',
    apis: ['user:list', 'authToken:list'],
    settings: {
        auth_tokens_rotated_fail: {
            name: 'Auth Tokens Rotated Fail',
            description: 'Return a failing result when auth tokens exceed this number of days without being rotated',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: '90'
        }
    },

    run: function (cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.objectFirstKey(cache['regionSubscription']['list']);

        var config = {
            auth_tokens_rotated_fail: parseInt(settings.auth_tokens_rotated_fail || this.settings.auth_tokens_rotated_fail.default)
        }

        var users = helpers.addSource(cache, source,
            ['user', 'list', region]);

        var authTokens = helpers.addSource(cache, source,
            ['authToken', 'list', region]);

        if (!users || !authTokens) return callback(null, results, source);

        if (users.err || !users.data) {
            helpers.addResult(results, 3,
                'Unable to query for users: ' + helpers.addError(users), 'global');
            return callback(null, results, source);
        }

        if (!users.data.length) {
            helpers.addResult(results, 0, 'No user accounts found', 'global');
            return callback(null, results, source);
        }

        if (authTokens.err || !authTokens.data) {
            helpers.addResult(results, 3,
                'Unable to query user auth tokens: ' + helpers.addError(authTokens), 'global');
            return callback(null, results, source);
        }

        if (!authTokens.data.length) {
            helpers.addResult(results, 0, 'No user auth tokens found', 'global');
            return callback(null, results, source);
        }

        for (let token of authTokens.data) {
            if (!token.id) continue;

            let timeCreated = token.timeCreated ? token.timeCreated : new Date();
            let difference = helpers.daysBetween(timeCreated, new Date());

            if (difference > config.auth_tokens_rotated_fail) {
                helpers.addResult(results, 2, `Auth token is ${difference} days old`, 'global', token.id);
            } else {
                helpers.addResult(results, 0, `Auth token is ${difference} days old`, 'global', token.id);
            }
        }

        callback(null, results, source);
    }
};

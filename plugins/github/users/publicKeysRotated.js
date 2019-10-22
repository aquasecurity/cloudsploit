var async = require('async');
var helpers = require('../../../helpers/github');

module.exports = {
    title: 'Public Keys Rotated',
    category: 'Users',
    types: ['user'],
    description: 'Ensures GitHub user keys are rotated frequently.',
    more_info: 'GitHub keys provide full access to repositories within an account and should be rotated every 180 days.',
    link: 'https://help.github.com/articles/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent/',
    recommended_action: 'Invalidate and delete old SSH public keys and create new ones every 180 days.',
    apis: ['users:listPublicKeys'],
    settings: {
        github_public_keys_rotated_fail: {
            name: 'GitHub Public Keys Rotated Fail',
            description: 'Return a failing result when public keys exceed this number of days without being rotated',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: 365
        },
        github_public_keys_rotated_warn: {
            name: 'GitHub Public Keys Rotated Warn',
            description: 'Return a warning result when public keys exceed this number of days without being rotated',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: 180
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            github_public_keys_rotated_fail: settings.github_public_keys_rotated_fail || this.settings.github_public_keys_rotated_fail.default,
            github_public_keys_rotated_warn: settings.github_public_keys_rotated_warn || this.settings.github_public_keys_rotated_warn.default
        };

        var custom = helpers.isCustom(settings, this.settings);

        var results = [];
        var source = {};

        var listPublicKeys = helpers.addSource(cache, source,
                ['users', 'listPublicKeys']);

        if (!listPublicKeys) return callback(null, results, source);

        if (listPublicKeys.err || !listPublicKeys.data) {
            helpers.addResult(results, 3,
                'Unable to query for user public keys: ' + helpers.addError(listPublicKeys));
            return callback(null, results, source);
        }

        if (!listPublicKeys.data.length) {
            helpers.addResult(results, 0, 'No user public keys found');
            return callback(null, results, source);
        }

        for (p in listPublicKeys.data) {
            var key = listPublicKeys.data[p];
            var keyName = key.title || 'unnamed';
            var keyResourceName = key.url || 'unknown';

            if (key.created_at) {
                var returnMsg = 'User public key: ' + keyName + ' was last rotated ' + helpers.daysAgo(key.created_at) + ' days ago';
                var returnCode = 0;

                if (helpers.daysAgo(key.created_at) > config.github_public_keys_rotated_fail) {
                    returnCode = 2;
                } else if (helpers.daysAgo(key.created_at) > config.github_public_keys_rotated_warn) {
                    returnCode = 1;
                }

                helpers.addResult(results, returnCode, returnMsg, 'global', keyResourceName, custom);
            } else {
                helpers.addResult(results, 3,
                    'User public key: '  + keyName + ' does not have a created date', 'global', keyResourceName, custom);
            }
        }

        callback(null, results, source);
    }
};
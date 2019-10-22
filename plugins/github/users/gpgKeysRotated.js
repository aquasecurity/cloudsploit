var async = require('async');
var helpers = require('../../../helpers/github');

module.exports = {
    title: 'GPG Keys Rotated',
    category: 'Users',
    types: ['user'],
    description: 'Ensures GitHub GPG keys are rotated frequently.',
    more_info: 'GitHub GPG keys are used to cryptographically sign code commits and should be rotated every 180 days.',
    link: 'https://help.github.com/articles/generating-a-new-gpg-key/',
    recommended_action: 'Invalidate and delete old GPG keys and create new ones every 180 days.',
    apis: ['users:listGpgKeys'],
    settings: {
        github_gpg_keys_rotated_fail: {
            name: 'GitHub GPG Keys Rotated Fail',
            description: 'Return a failing result when GPG keys exceed this number of days without being rotated',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: 365
        },
        github_gpg_keys_rotated_warn: {
            name: 'GitHub GPG Keys Rotated Warn',
            description: 'Return a warning result when GPG keys exceed this number of days without being rotated',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: 180
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            github_gpg_keys_rotated_fail: settings.github_gpg_keys_rotated_fail || this.settings.github_gpg_keys_rotated_fail.default,
            github_gpg_keys_rotated_warn: settings.github_gpg_keys_rotated_warn || this.settings.github_gpg_keys_rotated_warn.default
        };

        var custom = helpers.isCustom(settings, this.settings);

        var results = [];
        var source = {};

        var listGpgKeys = helpers.addSource(cache, source,
                ['users', 'listGpgKeys']);

        if (!listGpgKeys) return callback(null, results, source);

        if (listGpgKeys.err || !listGpgKeys.data) {
            helpers.addResult(results, 3,
                'Unable to query for user GPG keys: ' + helpers.addError(listGpgKeys));
            return callback(null, results, source);
        }

        if (!listGpgKeys.data.length) {
            helpers.addResult(results, 0, 'No user GPG keys found');
            return callback(null, results, source);
        }

        for (p in listGpgKeys.data) {
            var key = listGpgKeys.data[p];
            var keyName = key.title || 'unnamed';
            var keyResourceName = key.url || 'unknown';
            keyResourceName += ':' + keyName;

            if (key.created_at) {
                var returnMsg = 'User GPG key ' + keyName + ' was last rotated ' + helpers.daysAgo(key.created_at) + ' days ago';
                var returnCode = 0;

                if (helpers.daysAgo(key.created_at) > config.github_gpg_keys_rotated_fail) {
                    returnCode = 2;
                } else if (helpers.daysAgo(key.created_at) > config.github_gpg_keys_rotated_warn) {
                    returnCode = 1;
                }

                helpers.addResult(results, returnCode, returnMsg, 'global', keyResourceName, custom);
            } else {
                helpers.addResult(results, 3,
                    'User GPG key: '  + keyName + ' does not have a created date', 'global', keyResourceName, custom);
            }
        }

        callback(null, results, source);
    }
};
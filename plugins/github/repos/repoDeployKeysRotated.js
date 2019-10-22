var async = require('async');
var helpers = require('../../../helpers/github');

module.exports = {
    title: 'Repo Deploy Keys Rotated',
    types: ['org', 'user'],
    category: 'Repos',
    description: 'Ensures deploy keys associated with a repository are rotated regularly.',
    more_info: 'Deploy keys can have significant access to a repository and should be rotated on a regular basis.',
    link: 'https://developer.github.com/v3/guides/managing-deploy-keys/',
    recommended_action: 'Create a new deploy key in GitHub, update the associated applications, and then delete the old key from GitHub.',
    apis: ['apps:listRepos', 'repos:listDeployKeys'],
    settings: {
        repo_deploy_keys_rotated_fail: {
            name: 'Repo Deploy Keys Rotated Fail',
            description: 'Return a failing result when repo deploy keys exceed this number of days without being rotated',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: 365
        },
        repo_deploy_keys_rotated_warn: {
            name: 'Repo Deploy Keys Rotated Warn',
            description: 'Return a warning result when repo deploy keys exceed this number of days without being rotated',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: 180
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var config = {
            repo_deploy_keys_rotated_fail: settings.repo_deploy_keys_rotated_fail || this.settings.repo_deploy_keys_rotated_fail.default,
            repo_deploy_keys_rotated_warn: settings.repo_deploy_keys_rotated_warn || this.settings.repo_deploy_keys_rotated_warn.default
        };

        var custom = helpers.isCustom(settings, this.settings);

        var listRepos = helpers.addSource(cache, source,
            ['apps', 'listRepos']);

        if (!listRepos || !listRepos.data || listRepos.err) {
            helpers.addResult(results, 3,
                'Unable to query for repos: ' + helpers.addError(listRepos));
            return callback(null, results, source);
        }

        if (!listRepos.data.length) {
            helpers.addResult(results, 0, 'No repositories found.');
            return callback(null, results, source);
        }

        for (r in listRepos.data) {
            var repo = listRepos.data[r];
            var resource = helpers.getResource(repo);

            var listDeployKeys = helpers.addSource(cache, source,
                ['repos', 'listDeployKeys', repo.name]);

            if (!listDeployKeys || !listDeployKeys.data || listDeployKeys.err) {
                helpers.addResult(results, 3,
                    'Unable to list deploy keys for repo: ' + repo.full_name + ': ' + helpers.addError(listDeployKeys), 'global', resource);
                continue;
            }

            if (!listDeployKeys.data.length) {
                helpers.addResult(results, 0, 'No deploy keys found for repository: ' + repo.full_name, 'global', resource);
                continue;
            }

            for (k in listDeployKeys.data) {
                var key = listDeployKeys.data[k];
                var keyName = key.title || 'unnamed';
                var keyResourceName = helpers.getResource(key);

                if (key.created_at) {
                    var returnMsg = 'Deploy key: ' + keyName + ' was last rotated ' + helpers.daysAgo(key.created_at) + ' days ago';
                    var returnCode = 0;

                    if (helpers.daysAgo(key.created_at) > config.repo_deploy_keys_rotated_fail) {
                        returnCode = 2;
                    } else if (helpers.daysAgo(key.created_at) > config.repo_deploy_keys_rotated_warn) {
                        returnCode = 1;
                    }

                    helpers.addResult(results, returnCode, returnMsg, 'global', keyResourceName, custom);
                } else {
                    helpers.addResult(results, 3,
                        'Deploy key: '  + keyName + ' does not have a created date', 'global', keyResourceName, custom);
                }
            }
        }

        return callback(null, results, source);
    }
};
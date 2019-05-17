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
	apis: ['apps:listRepos'],//, 'repos:listForOrg', 'repos:listDeployKeys'],
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

		var getRepos = helpers.addSource(cache, source,
			['apps', 'listRepos']);

		for (d in getRepos.data.repositories) {
			console.log(getRepos.data.repositories[d].full_name);
		}

		var getReposForOrg = helpers.addSource(cache, source,
			['repos', 'listForOrg']);

		if (!getRepos && !getReposForOrg) return callback(null, results, source);

		if (!getRepos.data && !getReposForOrg.data) {
			helpers.addResult(results, 3,
				'Unable to query for repos: ' + helpers.addError(getRepos));
			return callback(null, results, source);
		}

		var repos = getRepos.data ? getRepos.data : getReposForOrg.data;

		for (r in repos) {
			var repo = repos[r];
			var resource = helpers.getResource(repo);

			var listDeployKeys = helpers.addSource(cache, source,
				['repos', 'listDeployKeys', repo.name]);

			if (!listDeployKeys || !listDeployKeys.data || listDeployKeys.err) {
				helpers.addResult(results, 3,
					'Unable to list deploy keys for repo: ' + helpers.addError(listDeployKeys), resource);
				continue;
			}

			console.log(listDeployKeys);
		}

		return callback(null, results, source);
	}
};
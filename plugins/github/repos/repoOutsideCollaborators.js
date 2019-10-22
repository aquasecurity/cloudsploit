var async = require('async');
var helpers = require('../../../helpers/github');

module.exports = {
    title: 'Repo Outside Collaborators',
    types: ['org'],
    category: 'Repos',
    description: 'Ensures organization repositories do not have outside collaborators with admin or push permissions.',
    more_info: 'Allowing outside collaborators admin or push access to organization repositories places the organization at risk from non-member contributions that can be pushed without review.',
    link: 'https://help.github.com/en/articles/adding-outside-collaborators-to-repositories-in-your-organization',
    recommended_action: 'For outside collaborators that need access to organization code, provide read access and require the collaborator to fork the repo and submit a pull request that can be reviewed by organization members.',
    apis: ['apps:listRepos', 'repos:listCollaborators', 'orgs:listMembers'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var listRepos = helpers.addSource(cache, source,
            ['apps', 'listRepos']);

        var listMembers = helpers.addSource(cache, source,
            ['orgs', 'listMembers']);

        if (!listRepos || !listRepos.data || listRepos.err) {
            helpers.addResult(results, 3,
                'Unable to query for repos: ' + helpers.addError(listRepos));
            return callback(null, results, source);
        }

        if (!listMembers || !listMembers.data || listMembers.err) {
            helpers.addResult(results, 3,
                'Unable to query for members: ' + helpers.addError(listMembers));
            return callback(null, results, source);
        }

        if (!listRepos.data.length) {
            helpers.addResult(results, 0, 'No repositories found.');
            return callback(null, results, source);
        }

        if (!listMembers.data.length) {
            helpers.addResult(results, 0, 'No members found.');
            return callback(null, results, source);
        }

        // Create list of organization members
        var orgMembers = [];

        for (m in listMembers.data) {
            orgMembers.push(listMembers.data[m].login);
        }

        for (r in listRepos.data) {
            var repo = listRepos.data[r];
            var resource = helpers.getResource(repo);

            var listCollaborators = helpers.addSource(cache, source,
                ['repos', 'listCollaborators', repo.name]);

            if (!listCollaborators || !listCollaborators.data || listCollaborators.err) {
                helpers.addResult(results, 3,
                    'Unable to list collaborators for repo: ' + repo.full_name + ': ' + helpers.addError(listCollaborators), 'global', resource);
                continue;
            }

            if (!listCollaborators.data.length) {
                helpers.addResult(results, 0, 'No collaborators found for repository: ' + repo.full_name, 'global', resource);
                continue;
            }

            var outside = {admin:[], push: [], pull: []};

            for (c in listCollaborators.data) {
                var collaborator = listCollaborators.data[c];

                // If the collaborator is not part of the organization
                if (orgMembers.indexOf(collaborator.login) == -1) {
                    for (p in collaborator.permissions) {
                        if (collaborator.permissions[p] && outside[p]) outside[p].push(collaborator);
                    }
                }
            }

            // Analyze outside collaborators
            var message = 'Repository has outside collaborators with the following permissions:' +
                          ' Admin: ' + outside.admin.length +
                          ' Push: ' + outside.push.length +
                          ' Pull: ' + outside.push.length;

            var result = 0;

            if (outside.admin.length) {
                result = 2;
            } else if (outside.push.length) {
                result = 1;
            }

            helpers.addResult(results, result, message, 'global', resource);
        }

        return callback(null, results, source);
    }
};
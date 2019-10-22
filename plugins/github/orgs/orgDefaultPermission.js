var async = require('async');
var helpers = require('../../../helpers/github');

module.exports = {
    title: 'Org Default Permission',
    types: ['org'],
    category: 'Orgs',
    description: 'Checks the default permission given to new users added to an organization.',
    more_info: 'The default permission given to new organization users should be set to none. Read permissions risk exposing private repositories, while write or admin permissions risk sensitive access to repositories for new users.',
    link: 'https://help.github.com/en/articles/repository-permission-levels-for-an-organization',
    recommended_action: 'Set the default permission to none or read-only and assign permissions on a more granular repository level.',
    apis: ['orgs:get'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var getOrg = helpers.addSource(cache, source,
            ['orgs', 'get']);

        if (!getOrg) return callback(null, results, source);

        if (getOrg.err || !getOrg.data) {
            helpers.addResult(results, 3,
                'Unable to query for organization permission information: ' + helpers.addError(getOrg));
            return callback(null, results, source);
        }

        if (!getOrg.data.default_repository_permission ||
            getOrg.data.default_repository_permission == 'none') {
            helpers.addResult(results, 0, 'The default organization permission level is set to none.');
        } else if (getOrg.data.default_repository_permission == 'read') {
            helpers.addResult(results, 1, 'The default organization permission level is set to read-only.');
        } else if (getOrg.data.default_repository_permission == 'write') {
            helpers.addResult(results, 2, 'The default organization permission level is set to write.');
        } else if (getOrg.data.default_repository_permission == 'admin') {
            helpers.addResult(results, 2, 'The default organization permission level is set to admin.');
        }

        return callback(null, results, source);
    }
};
var async = require('async');
var helpers = require('../../../helpers/github');

module.exports = {
    title: 'Org MFA Required',
    types: ['org'],
    category: 'Orgs',
    description: 'Checks whether multi-factor authentication is required at the org-level.',
    more_info: 'MFA should be enabled and enforced for all users of an organization.',
    link: 'https://help.github.com/en/articles/requiring-two-factor-authentication-in-your-organization',
    recommended_action: 'Enable the setting that requires two-factor authentication for everyone in the organization.',
    apis: ['orgs:get'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var getOrg = helpers.addSource(cache, source,
            ['orgs', 'get']);

        if (!getOrg) return callback(null, results, source);

        if (getOrg.err || !getOrg.data) {
            helpers.addResult(results, 3,
                'Unable to query for organization MFA information: ' + helpers.addError(getOrg));
            return callback(null, results, source);
        }

        if (!getOrg.data.two_factor_requirement_enabled ||
            getOrg.data.two_factor_requirement_enabled == 'none') {
            helpers.addResult(results, 2, 'MFA is not enforced for the organization.');
        } else {
            helpers.addResult(results, 0, 'MFA is enforced for the organization.');
        }

        return callback(null, results, source);
    }
};
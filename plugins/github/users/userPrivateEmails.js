var async = require('async');
var helpers = require('../../../helpers/github');

module.exports = {
    title: 'User Private Emails',
    category: 'Users',
    types: ['user'],
    description: 'Checks that the primary email addresse associated with a GitHub account is set to private visibility.',
    more_info: 'Email addresses added to GitHub should be set to private visibility to increase privacy and prevent account reconnaissance.',
    link: 'https://developer.github.com/v3/users/emails/#toggle-primary-email-visibility',
    recommended_action: 'Change the visibility of GitHub email addresses to private.',
    apis: ['users:listEmails'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var listEmails = helpers.addSource(cache, source,
            ['users', 'listEmails']);

        if (!listEmails) return callback(null, results, source);

        if (listEmails.err || !listEmails.data) {
            helpers.addResult(results, 3,
                'Unable to query for user email visibility: ' + helpers.addError(listEmails));
            return callback(null, results, source);
        }

        if (!listEmails.data.length) {
            helpers.addResult(results, 0, 'No GitHub email addresses found');
            return callback(null, results, source);
        }

        var found = false;

        for (e in listEmails.data) {
            var email = listEmails.data[e];
            if (!email.primary) continue;
            found = true;

            if (email.visibility == 'private') {
                helpers.addResult(results, 0, 'Primary email address visibility is set to private', 'global', email.email);
            } else {
                helpers.addResult(results, 1, 'Primary email address visibility is set to public', 'global', email.email);
            }
        }

        if (!found) {
            helpers.addResult(results, 0, 'No primary email address set.', 'global', 'N/A');
        }

        callback(null, results, source);
    }
};
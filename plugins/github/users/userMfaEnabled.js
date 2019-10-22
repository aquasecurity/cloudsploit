var async = require('async');
var helpers = require('../../../helpers/github');

module.exports = {
    title: 'User MFA Enabled',
    category: 'Users',
    types: ['user'],
    description: 'Ensures multi-factor authentication is enabled for the default user account',
    more_info: 'GitHub MFA provides additional account security by requiring an additional login device or code. All accounts should have MFA enabled.',
    link: 'https://help.github.com/articles/securing-your-account-with-two-factor-authentication-2fa/',
    recommended_action: 'Enable MFA on the default user account.',
    apis: ['users:getAuthenticated'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var getAuthenticated = helpers.addSource(cache, source,
            ['users', 'getAuthenticated']);

        if (!getAuthenticated) return callback(null, results, source);

        if (getAuthenticated.err || !getAuthenticated.data) {
            helpers.addResult(results, 3,
                'Unable to query for user MFA status: ' + helpers.addError(getAuthenticated));
            return callback(null, results, source);
        }

        if (getAuthenticated.data.two_factor_authentication) {
            helpers.addResult(results, 0, 'User MFA is enabled', 'global', getAuthenticated.data.url || 'N/A');
        } else {
            helpers.addResult(results, 2, 'User MFA is not enabled', 'global', getAuthenticated.data.url || 'N/A');
        }

        callback(null, results, source);
    }
};
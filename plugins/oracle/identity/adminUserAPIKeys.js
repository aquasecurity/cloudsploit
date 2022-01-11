var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Admin User API Keys',
    category: 'Identity',
    domain: 'Identity and Access Management',
    description: 'Ensure that API keys do not exist for tenancy administrator users.',
    more_info: 'The administrator user should avoid using API keys. Since the administrator user has full permissions across the entire tenancy, creating API keys for it only increases the chance that they are compromised. ' +
        'Instead, create non-admin user with limited permissions and use its API keys.',
    link: 'https://docs.oracle.com/en/cloud/get-started/subscriptions-cloud/csgsg/create-users-and-assign-roles.html',
    recommended_action: 'Remove API keys for administrator users',
    apis: ['user:list', 'apiKey:list', 'group:list', 'userGroupMembership:list', 'authToken:list'],

    run: function (cache, settings, callback) {
        var results = [];
        var source = {};

        var region = helpers.objectFirstKey(cache['regionSubscription']['list']);

        var users = helpers.addSource(cache, source,
            ['user', 'list', region]);

        var groups = helpers.addSource(cache, source,
            ['group', 'list', region]);

        var userGroups = helpers.addSource(cache, source,
            ['userGroupMembership', 'list', region]);

        var apiKeys = helpers.addSource(cache, source,
            ['apiKey', 'list', region]);

        if (!users || !groups || !userGroups || !apiKeys) return callback(null, results, source);

        if (users.err || !users.data) {
            helpers.addResult(results, 3,
                'Unable to query for users: ' + helpers.addError(users), 'global');
            return callback(null, results, source);
        }

        if (!users.data.length) {
            helpers.addResult(results, 0, 'No user accounts found', 'global');
            return callback(null, results, source);
        }

        if (groups.err || !groups.data) {
            helpers.addResult(results, 3,
                'Unable to query user groups: ' + helpers.addError(groups), 'global');
            return callback(null, results, source);
        }

        if (!groups.data.length) {
            helpers.addResult(results, 0, 'No groups found', 'global');
            return callback(null, results, source);
        }

        if (userGroups.err || !userGroups.data) {
            helpers.addResult(results, 3,
                'Unable to query user groups: ' + helpers.addError(userGroups), 'global');
            return callback(null, results, source);
        }

        if (!userGroups.data.length) {
            helpers.addResult(results, 0, 'No user group membership found', 'global');
            return callback(null, results, source);
        }

        if (apiKeys.err || !apiKeys.data) {
            helpers.addResult(results, 3,
                'Unable to query user API keys: ' + helpers.addError(apiKeys), 'global');
            return callback(null, results, source);
        }

        if (!apiKeys.data.length) {
            helpers.addResult(results, 0, 'No user API keys found', 'global');
            return callback(null, results, source);
        }

        let adminGroup = groups.data.find(group => group.name == 'Administrators');
        let apiKeyIds = apiKeys.data.map(apiKey => apiKey.userId) || [];

        if (adminGroup) {

            let adminUsers = userGroups.data.map(userGroup => userGroup.userId) || [];

            for (let user of users.data) {
                if (!user.id) continue;

                if (adminUsers.includes(user.id)) {
                    if (apiKeyIds.includes(user.id)) {
                        helpers.addResult(results, 2, 'API keys exist for admin user', 'global', user.id);
                    } else {
                        helpers.addResult(results, 0, 'API key does not exist for admin user', 'global', user.id);
                    }
                } else {
                    helpers.addResult(results, 0, 'User is not admin user', 'global', user.id);
                }
            }
        } else {
            helpers.addResult(results, 0, 'No groups found');
        }

        callback(null, results, source);
    }
};

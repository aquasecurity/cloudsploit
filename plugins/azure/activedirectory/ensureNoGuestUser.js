const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Ensure No Guest User',
    category: 'Active Directory',
    description: 'Ensures that there are no guest users in the subscription',
    more_info: 'Guest users are usually users that are invited from outside the company structure, these users are not part of the onboarding/offboarding process and could be overlooked, causing security vulnerabilities.',
    link: 'https://docs.microsoft.com/en-us/azure/active-directory/b2b/add-users-administrator',
    recommended_action: 'Remove all guest users unless they are required to be members of the Active Directory account.',
    apis: ['users:list'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.users, function(location, rcb) {

            const users = helpers.addSource(cache, source,
                ['users', 'list', location]);

            if (!users) return rcb();

            if (users.err || !users.data) {
                helpers.addResult(results, 3, 'Unable to query for users: ' + helpers.addError(users), location);
                return rcb();
            }
            if (!users.data.length) {
                helpers.addResult(results, 0, 'No existing users found', location);
                return rcb();
            }

            var guestUser = false;
            users.data.forEach(user => {
                if (user.userType === 'Guest') {
                    helpers.addResult(results, 2, 'The user is a guest user', location, user.mail);
                    guestUser = true;
                }
            });

            if (!guestUser) {
                helpers.addResult(results, 0, 'The subscription does not have any guest users', location);
            }
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};

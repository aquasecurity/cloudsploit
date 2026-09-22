const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Disabled User Role Assignments',
    category: 'Entra ID',
    domain: 'Identity and Access Management',
    severity: 'Medium',
    description: 'Ensures that disabled user accounts do not have role assignments.',
    more_info: 'Disabled user accounts retain their role assignments by default. Removing role assignments from disabled accounts ensures that access is revoked when an account is blocked and enforces the principle of least privilege.',
    recommended_action: 'Remove role assignments from disabled user accounts.',
    link: 'https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-remove',
    apis: ['users:list', 'aad:listRoleAssignments'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.aad, function(location, rcb) {

            const users = helpers.addSource(cache, source,
                ['users', 'list', location]);

            if (!users) return rcb();

            if (users.err || !users.data) {
                helpers.addResult(results, 3, 'Unable to query for users: ' + helpers.addError(users), location);
                return rcb();
            }

            const roleAssignments = helpers.addSource(cache, source,
                ['aad', 'listRoleAssignments', location]);

            if (!roleAssignments) return rcb();

            if (roleAssignments.err || !roleAssignments.data) {
                helpers.addResult(results, 3, 'Unable to query for role assignments: ' + helpers.addError(roleAssignments), location);
                return rcb();
            }

            var disabledUsers = users.data.filter(user => user.id && user.accountEnabled === false);

            if (!disabledUsers.length) {
                helpers.addResult(results, 0, 'No disabled user accounts found', location);
                return rcb();
            }

            var assignedPrincipals = roleAssignments.data.filter(roleAssignment => roleAssignment.principalId)
                .map(roleAssignment => roleAssignment.principalId);

            disabledUsers.forEach(user => {
                if (assignedPrincipals.includes(user.id)) {
                    helpers.addResult(results, 2, 'Disabled user account has role assignments', location, user.id);
                } else {
                    helpers.addResult(results, 0, 'Disabled user account does not have role assignments', location, user.id);
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};

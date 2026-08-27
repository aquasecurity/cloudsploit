const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'User Access Administrator Role Restricted',
    category: 'Entra ID',
    domain: 'Identity and Access Management',
    severity: 'Medium',
    description: 'Ensures that the User Access Administrator role is not assigned.',
    more_info: 'The User Access Administrator role allows viewing all resources and managing access assignments across the tenant. Because of its high privilege level, the role assignment should be removed once the required changes are complete to reduce the risk of privilege escalation and unauthorized access.',
    recommended_action: 'Remove User Access Administrator role assignments that are no longer required.',
    link: 'https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#user-access-administrator',
    apis: ['roleDefinitions:list', 'aad:listRoleAssignments'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.aad, function(location, rcb) {

            const roleDefinitions = helpers.addSource(cache, source,
                ['roleDefinitions', 'list', location]);

            if (!roleDefinitions) return rcb();

            if (roleDefinitions.err || !roleDefinitions.data) {
                helpers.addResult(results, 3, 'Unable to query for role definitions: ' + helpers.addError(roleDefinitions), location);
                return rcb();
            }

            const roleAssignments = helpers.addSource(cache, source,
                ['aad', 'listRoleAssignments', location]);

            if (!roleAssignments) return rcb();

            if (roleAssignments.err || !roleAssignments.data) {
                helpers.addResult(results, 3, 'Unable to query for role assignments: ' + helpers.addError(roleAssignments), location);
                return rcb();
            }

            var adminRoleIds = roleDefinitions.data.filter(roleDefinition => roleDefinition.roleName &&
                roleDefinition.roleName.toLowerCase() === 'user access administrator' && roleDefinition.id)
                .map(roleDefinition => roleDefinition.id.split('/').pop());

            if (!adminRoleIds.length) {
                helpers.addResult(results, 0, 'No User Access Administrator role definition found', location);
                return rcb();
            }

            var adminAssignments = roleAssignments.data.filter(roleAssignment => roleAssignment.roleDefinitionId &&
                adminRoleIds.includes(roleAssignment.roleDefinitionId.split('/').pop()));

            if (!adminAssignments.length) {
                helpers.addResult(results, 0, 'User Access Administrator role is not assigned', location);
                return rcb();
            }

            adminAssignments.forEach(roleAssignment => {
                helpers.addResult(results, 2, 'User Access Administrator role is assigned', location, roleAssignment.id);
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};

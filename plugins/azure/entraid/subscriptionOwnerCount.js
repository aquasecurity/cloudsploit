const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Subscription Owner Count',
    category: 'Entra ID',
    domain: 'Identity and Access Management',
    severity: 'Medium',
    description: 'Ensures that the number of subscription owners is within the desired range.',
    more_info: 'The Owner role grants full control over all resources in a subscription, including the ability to assign roles to others. Keeping the number of owners low limits privilege sprawl, while keeping more than one avoids losing administrative access. All principal types count towards the total, including users, groups, service principals and managed identities.',
    recommended_action: 'Remove unnecessary Owner role assignments, or add an additional owner if only one exists.',
    link: 'https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#owner',
    apis: ['roleDefinitions:list', 'aad:listRoleAssignments'],
    settings: {
        subscription_owners_min: {
            name: 'Subscription Owners Minimum',
            description: 'Return a failing result when the number of subscription owners is below this value',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: 2
        },
        subscription_owners_max: {
            name: 'Subscription Owners Maximum',
            description: 'Return a failing result when the number of subscription owners exceeds this value',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: 3
        }
    },

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        var config = {
            subscription_owners_min: parseInt(settings.subscription_owners_min || this.settings.subscription_owners_min.default),
            subscription_owners_max: parseInt(settings.subscription_owners_max || this.settings.subscription_owners_max.default)
        };

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

            var ownerRoleIds = roleDefinitions.data.filter(roleDefinition => roleDefinition.roleName &&
                roleDefinition.roleName.toLowerCase() === 'owner' && roleDefinition.id)
                .map(roleDefinition => roleDefinition.id.split('/').pop());

            if (!ownerRoleIds.length) {
                helpers.addResult(results, 0, 'No Owner role definition found', location);
                return rcb();
            }

            var owners = roleAssignments.data.filter(roleAssignment => roleAssignment.roleDefinitionId &&
                ownerRoleIds.includes(roleAssignment.roleDefinitionId.split('/').pop()) &&
                roleAssignment.scope && !roleAssignment.scope.toLowerCase().includes('/resourcegroups/'));

            if (owners.length < config.subscription_owners_min) {
                helpers.addResult(results, 2, `Subscription has ${owners.length} owners, fewer than the desired minimum of ${config.subscription_owners_min}`, location);
            } else if (owners.length > config.subscription_owners_max) {
                helpers.addResult(results, 2, `Subscription has ${owners.length} owners, more than the desired maximum of ${config.subscription_owners_max}`, location);
            } else {
                helpers.addResult(results, 0, `Subscription has ${owners.length} owners`, location);
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};

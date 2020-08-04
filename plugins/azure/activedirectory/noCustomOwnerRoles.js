const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'No Custom Owner Roles',
    category: 'Active Directory',
    description: 'Ensures that no custom owner roles exist.',
    more_info: 'Subscription owners should not include permissions to create custom owner roles. This follows the principle of least privilege.',
    link: 'https://docs.microsoft.com/en-us/azure/role-based-access-control/custom-roles',
    recommended_action: 'Remove roles that allow permissions to create custom owner roles.',
    apis: ['roleDefinitions:list'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.roleDefinitions, function(location, rcb) {

            const roleDefinitions = helpers.addSource(cache, source,
                ['roleDefinitions', 'list', location]);

            if (!roleDefinitions) return rcb();

            if (roleDefinitions.err || !roleDefinitions.data) {
                helpers.addResult(results, 3, 'Unable to query for role definitions: ' + helpers.addError(roleDefinitions), location);
                return rcb();
            }

            if (!roleDefinitions.data.length) {
                helpers.addResult(results, 0, 'No role definitions found', location);
                return rcb();
            }

            var customRoles = [];
            
            roleDefinitions.data.forEach(roleDefinition => {
                if (roleDefinition.roleType && roleDefinition.roleType !== 'BuiltInRole') {
                    customRoles.push(roleDefinition);
                }
            });

            if (!customRoles.length) {
                helpers.addResult(results, 0,'No custom roles found', location);
                return rcb();
            }

            customRoles.forEach(function(roleDefinition) {
                var subscription = roleDefinition.id.split('/').slice(0, 3).join('/');
                var subAlone = subscription.split('/').slice(2, 3).join('/');
                var action = false;
                var scope = false;

                if (roleDefinition.permissions &&
                    roleDefinition.permissions.length) {
                    roleDefinition.permissions.forEach(permission => {
                        if (permission.actions &&
                            (permission.actions.indexOf('*') > -1)) {
                            action = true;
                        }
                    });
                }
                if (roleDefinition.assignableScopes &&
                    ((roleDefinition.assignableScopes.indexOf('/') > -1) ||
                        (roleDefinition.assignableScopes.indexOf(subAlone) > -1) ||
                        (roleDefinition.assignableScopes.indexOf(subscription) > -1))) {
                    scope = true;
                }

                if (action && scope) {
                    helpers.addResult(results, 2, 'Permission to create custom owner roles enabled', location, roleDefinition.id);
                } else {
                    helpers.addResult(results, 0, 'Permission to create custom owner roles is not enabled', location, roleDefinition.id);
                }
            });
            
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};

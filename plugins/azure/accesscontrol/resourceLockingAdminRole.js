const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Resource Locking Admin Role',
    category: 'Access Control',
    domain: 'Identity and Access Management',
    description: 'Ensure there is a custom IAM role assigned to manage resource locking within each Microsoft Azure subscription.',
    more_info: 'Azure resource locks enable you to restrict operations on production Azure cloud resources where modifying or deleting a resource would have a significant negative impact.',
    recommended_action: 'Create an IAM role to manage the resource locking for each Azure subscription.',
    link: 'https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources',
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
                        if (permission.actions && permission.actions) {
                            permission.actions.forEach(ac => {
                                if (ac.indexOf('locks') > -1) {
                                    action = true;
                                }
                            });
                        }
                    });
                }

                if (roleDefinition.assignableScopes) {
                    roleDefinition.assignableScopes.forEach(sc => {
                        if ((sc.indexOf('/') > -1) || (sc.indexOf(subAlone) > -1) || (sc.indexOf(subscription) > -1)) {
                            scope = true;
                        }
                    });
                }

                if (action && scope) {
                    helpers.addResult(results, 0, 'Resource locking administrator role is enabled for current subscription', location, roleDefinition.id);
                } else {
                    helpers.addResult(results, 2, 'Resource locking administrator role is not enabled for current subscription', location, roleDefinition.id);
                }
            });
            
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

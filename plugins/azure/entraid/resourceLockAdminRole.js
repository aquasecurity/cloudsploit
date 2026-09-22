const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Resource Lock Administrator Role',
    category: 'Entra ID',
    domain: 'Identity and Access Management',
    severity: 'Low',
    description: 'Ensures that a custom role is assigned permissions for administering resource locks.',
    more_info: 'Resource locks prevent inadvertent modification or deletion of resources. Managing locks requires the Microsoft.Authorization/locks permission, which is otherwise only available through broad roles such as Owner or User Access Administrator. Creating a custom role limited to lock administration follows the principle of least privilege.',
    recommended_action: 'Create a custom role granting the Microsoft.Authorization/locks permission and assign it to the members responsible for administering resource locks.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources',
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

            var lockRole = roleDefinitions.data.find(roleDefinition => roleDefinition.roleType &&
                roleDefinition.roleType.toLowerCase() === 'customrole' &&
                (roleDefinition.permissions || []).some(permission => (permission.actions || []).some(action =>
                    action.toLowerCase().startsWith('microsoft.authorization/locks'))));

            if (lockRole) {
                helpers.addResult(results, 0, 'Custom role for administering resource locks exists', location, lockRole.id);
            } else {
                helpers.addResult(results, 2, 'No custom role for administering resource locks found', location);
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};

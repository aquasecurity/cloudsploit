var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'VM System-Assigned Identity Enabled',
    category: 'Virtual Machines',
    domain: 'Compute',
    severity: 'Medium',
    description: 'Ensures that virtual machines have system-assigned managed identities enabled.',
    more_info: 'System-assigned managed identities for Azure VMs allow authentication to other services without the need to manage and store credentials in code.',
    recommended_action: 'Modify virtual machine and enable system-assigned managed identity.',
    link: 'https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/qs-configure-portal-windows-vm',
    apis: ['virtualMachines:listAll'],
    realtime_triggers: ['microsoftcompute:virtualmachines:write', 'microsoftcompute:virtualmachines:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.virtualMachines, function(location, rcb) {
            var virtualMachines = helpers.addSource(cache, source,
                ['virtualMachines', 'listAll', location]);

            if (!virtualMachines) return rcb();

            if (virtualMachines.err || !virtualMachines.data) {
                helpers.addResult(results, 3, 'Unable to query for virtualMachines: ' + helpers.addError(virtualMachines), location);
                return rcb();
            }

            if (!virtualMachines.data.length) {
                helpers.addResult(results, 0, 'No existing Virtual Machines found', location);
                return rcb();
            }

            for (let vm of virtualMachines.data) {
                if (!vm.id) continue;

                if (vm.identity && vm.identity.type && vm.identity.type.toLowerCase() === 'systemassigned'){
                    helpers.addResult(results, 0, 'Virtual Machine has system assigned managed identity enabled', location, vm.id);
                } else {
                    helpers.addResult(results, 2, 'Virtual Machine does not have system assigned managed identity enabled', location, vm.id);
                }
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
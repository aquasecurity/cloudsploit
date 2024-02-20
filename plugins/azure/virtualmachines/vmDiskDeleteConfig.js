var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'VM Disks Deletion Config',
    category: 'Virtual Machines',
    domain: 'Compute',
    severity: 'Low',
    description: 'Ensure the option to automatically delete disks is enabled when the associated VM is terminated.',
    more_info: 'Disks persist independently from VMs. Enabling this option ensures that all disks associated with a VM are deleted automatically when the VM is terminated, enhancing security.',
    recommended_action: 'Configure VMs to automatically delete disks when the VM is terminated.',
    link: 'https://learn.microsoft.com/en-us/azure/virtual-machines/delete?tabs=portal2%2Ccli3%2Cportal4%2Cportal5',
    apis: ['virtualMachines:listAll'],
    realtime_triggers: ['microsoftcompute:disks:write', 'microsoftcompute:disks:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.virtualMachines, function(location, rcb) {
            var virtualMachines = helpers.addSource(cache, source,
                ['virtualMachines', 'listAll', location]);

            if (!virtualMachines) return rcb();

            if (virtualMachines.err || !virtualMachines.data) {
                helpers.addResult(results, 3, 'Unable to query for Virtual Machines: ' + helpers.addError(virtualMachines), location);
                return rcb();
            }

            if (!virtualMachines.data.length) {
                helpers.addResult(results, 0, 'No existing Virtual Machines found', location);
                return rcb();
            }

            virtualMachines.data.forEach(virtualMachine => {
                if (virtualMachine.storageProfile && virtualMachine.storageProfile.osDisk && virtualMachine.storageProfile.osDisk.deleteOption && virtualMachine.storageProfile.osDisk.deleteOption === 'Delete') {
                    helpers.addResult(results, 0, 'Automatic disks delete with VM is enabled', location, virtualMachine.id);
                } else {
                    helpers.addResult(results, 2, 'Automatic disks delete with VM is not enabled', location, virtualMachine.id);
                }
            });
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Azure VM"s Automatic Disks Delete Enabled',
    category: 'Virtual Machines',
    domain: 'Compute',
    description: 'Ensure the option to automatically delete disks is enabled when the associated VM is terminated to ensure all confidential information is wiped.',
    more_info: 'Disks persist independently from VMs. Enabling this option ensures that all disks associated with a VM are deleted automatically when the VM is terminated, enhancing security.',
    recommended_action: 'Configure VMs to automatically delete disks when the VM is terminated to enhance security and prevent lingering confidential information.',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-machines/extensions/disk-delete',
    apis: ['virtualMachines:listAll'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.virtualMachines, function(location, rcb) {
            var virtualMachines = helpers.addSource(cache, source,
                ['virtualMachines', 'listAll', location]);

            if (!virtualMachines) return rcb();

            if (virtualMachines.err || !virtualMachines.data) {
                helpers.addResult(results, 3, 'Unable to query for virtual machines: ' + helpers.addError(virtualMachines), location);
                return rcb();
            }

            if (!virtualMachines.data.length) {
                helpers.addResult(results, 0, 'No existing Virtual Machines found', location);
                return rcb();
            }

            virtualMachines.data.forEach(virtualMachine => {
                if (virtualMachine.storageProfile && virtualMachine.storageProfile.osDisk && virtualMachine.storageProfile.osDisk.deleteOption=='Delete') {
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

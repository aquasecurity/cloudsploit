var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'VM Managed Disks Enabled',
    category: 'Virtual Machines',
    domain: 'Compute',
    description: 'Ensures that Azure virtual machines are configured to use Azure managed disks.',
    more_info: 'Azure managed disks are block-level storage volumes that are managed by Azure are like physical disks in an on-premises server but, virtualized. Azure managed disks provide high durability and security.',
    recommended_action: 'Migrate virtual machine disks to Azure managed disks',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-machines/managed-disks-overview',
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
                helpers.addResult(results, 3, 'Unable to query for virtualMachines: ' + helpers.addError(virtualMachines), location);
                return rcb();
            }

            if (!virtualMachines.data.length) {
                helpers.addResult(results, 0, 'No existing Virtual Machines found', location);
                return rcb();
            }

            for (let virtualMachine of virtualMachines.data) {
                if (virtualMachine.storageProfile && virtualMachine.storageProfile.osDisk &&
                    virtualMachine.storageProfile.osDisk.managedDisk && virtualMachine.storageProfile.osDisk.managedDisk.id) {
                    helpers.addResult(results, 0, 'Virtual machine is configured to use Azure managed disks', location, virtualMachine.id);
                } else {
                    helpers.addResult(results, 2, 'Virtual machine is not configured to use Azure managed disks', location, virtualMachine.id);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
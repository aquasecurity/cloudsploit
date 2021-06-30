var async = require('async');

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Premium SSD Disabled',
    category: 'Virtual Machines',
    description: 'Ensures that the Azure virtual machines are configured to use standard SSD disk volumes instead of premium SSD disk volumes for managed disks.',
    more_info: 'Azure standard SSD disks store data on solid state drives (SSDs), like Azure\'s existing premium storage disks. Standard SSD disks are a cost-effective storage option optimized for workloads that need consistent performance at lower IOPS levels.',
    recommended_action: 'Modify virtual machines disks to use standard SSD disk volumes instead of premium SSD disk volumes',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-machines/disks-types',
    apis: ['virtualMachines:listAll'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.virtualMachines, function(location, rcb){
            const virtualMachines = helpers.addSource(cache, source, ['virtualMachines', 'listAll', location]);

            if (!virtualMachines) return rcb();

            if (virtualMachines.err || !virtualMachines.data) {
                helpers.addResult(results, 3, 'Unable to query for virtual machines: ' + helpers.addError(virtualMachines), location);
                return rcb();
            }
            if (!virtualMachines.data.length) {
                helpers.addResult(results, 0, 'No existing virtual machines found', location);
                return rcb();
            }
            
            virtualMachines.data.forEach(virtualMachine => {
                let foundDisk = false;
                if (virtualMachine.storageProfile && virtualMachine.storageProfile.osDisk &&
                    virtualMachine.storageProfile.osDisk.managedDisk && 
                    virtualMachine.storageProfile.osDisk.managedDisk.id &&
                    virtualMachine.storageProfile.osDisk.managedDisk.storageAccountType &&
                    virtualMachine.storageProfile.osDisk.managedDisk.storageAccountType.toLowerCase() === 'premium_lrs') {
                    helpers.addResult(results, 2, 'Attached OS disk volume is of Premium SSD type', location, virtualMachine.storageProfile.osDisk.managedDisk.id);
                    foundDisk = true;
                } else if (virtualMachine.storageProfile && virtualMachine.storageProfile.osDisk && virtualMachine.storageProfile.osDisk.managedDisk){
                    helpers.addResult(results, 0, 'Attached OS disk volume is not of Premium SSD type', location, virtualMachine.storageProfile.osDisk.managedDisk.id);
                    foundDisk = true;
                }

                const dataDisks = (virtualMachine.storageProfile && virtualMachine.storageProfile.dataDisks) ? virtualMachine.storageProfile.dataDisks : [];

                for (const dataDisk of dataDisks) {
                    if (dataDisk.managedDisk && dataDisk.managedDisk.storageAccountType && dataDisk.managedDisk.id &&
                        dataDisk.managedDisk.storageAccountType.toLowerCase() === 'premium_lrs') {
                        helpers.addResult(results, 2, 'Attached data disk volume is of Premium SSD type', location, dataDisk.managedDisk.id);
                        foundDisk = true;
                    } else if (dataDisk.managedDisk) {
                        helpers.addResult(results, 0, 'Attached data disk volume is not of Premium SSD type', location, dataDisk.managedDisk.id);
                        foundDisk = true;
                    }
                }
                if (!foundDisk) {
                    helpers.addResult(results, 0, 'No disks found for the Virtual machine', location, virtualMachine.id);
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
}; 

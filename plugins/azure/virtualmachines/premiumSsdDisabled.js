var async = require('async');

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Premium SSD Disabled',
    category: 'Virtual Machines',
    description: 'Ensures that the Azure virtual machines are configured to use standard SSD disk volumes.',
    more_info: 'Azure standard SSD disks store data on solid state drives (SSDs), like Azure\'s existing premium storage disks. Standard SSD disks are a cost-effective storage option optimized for workloads that need consistent performance at lower IOPS levels.',
    recommended_action: 'Modify virtual machines disks to use standard SSD disk volumes instead of premium SSD disk volumes',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-machines/disks-types',
    apis: ['disks:list', 'virtualMachines:listAll'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.disks, function(location, rcb){
            const virtualMachines = helpers.addSource(cache, source, ['virtualMachines', 'listAll', location]);
            const disks = helpers.addSource(cache, source, ['disks', 'list', location]);
            

            if (!virtualMachines || !disks) return rcb();

            if (virtualMachines.err || !virtualMachines.data) {
                helpers.addResult(results, 3, 'Unable to query for virtual machines: ' + helpers.addError(disks), location);
                return rcb();
            }
            if (!virtualMachines.data.length) {
                helpers.addResult(results, 0, 'No existing virtual machines found', location);
                return rcb();
            }

            if (disks.err || !disks.data) {
                helpers.addResult(results, 3, 'Unable to query for virtual machine disk volumes: ' + helpers.addError(disks), location);
                return rcb();
            }
            if (!disks.data.length) {
                helpers.addResult(results, 0, 'No existing disk volumes found for virtual machines', location);
                return rcb();
            }

            const disksMap = new Map();
            disks.data.forEach(disk => {
                if (disk.managedBy && disk.sku && disk.sku.tier) {
                    if (disksMap.get(disk.managedBy.toLowerCase())) {
                        disksMap.get(disk.managedBy.toLowerCase()).set(disk.id, disk.sku.tier);
                    } else {
                        disksMap.set(disk.managedBy.toLowerCase(), new Map());
                        disksMap.get(disk.managedBy.toLowerCase()).set(disk.id, disk.sku.tier);
                    }
                }
            });
            
            
            virtualMachines.data.forEach(virtualMachine => {
                const attachedDisks = disksMap.get(virtualMachine.id.toLowerCase());

                if (attachedDisks) {
                    attachedDisks.forEach((diskType, diskId) => {
                        if (diskType.toLowerCase() === 'standard') {
                            helpers.addResult(results, 0, 'Disk volume is of standard SSD type', location, diskId);
                        } else {
                            helpers.addResult(results, 2, 'Disk volume is not of standard SSD type', location, diskId);
                        }
                    });
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
}; 
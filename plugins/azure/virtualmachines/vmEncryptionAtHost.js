var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'VM Encryption At Host',
    category: 'Virtual Machines',
    domain: 'Compute',
    severity: 'High',
    description: 'Ensures that encryption at host is enabled for Azure Virtual Machine disks.',
    more_info: 'The data for temporary disk and OS/data disk caches is stored on the VM host. Enabling encryption at host for Azure Virtual Machine disks allows the data to be end-to-end encrypted, ensuring compliance and bolstering overall security with Azure Disk Encryption.',
    recommended_action: 'Ensure that all Azure Virtual Machines have encryption at host enabled for disks.',
    link: 'https://learn.microsoft.com/en-us/azure/virtual-machines/disk-encryption#encryption-at-host---end-to-end-encryption-for-your-vm-data',
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
                helpers.addResult(results, 3, 'Unable to query for Virtual Machines: ' + helpers.addError(virtualMachines), location);
                return rcb();
            }

            if (!virtualMachines.data.length) {
                helpers.addResult(results, 0, 'No existing Virtual Machines found', location);
                return rcb();
            }

            virtualMachines.data.forEach(virtualMachine => {
                if (virtualMachine.securityProfile && virtualMachine.securityProfile.encryptionAtHost) {
                    helpers.addResult(results, 0, 'Encryption at host is enabled for virtual machine disks', location, virtualMachine.id);
                } else {
                    helpers.addResult(results, 2, 'Encryption at host is not enabled for virtual machine disks', location, virtualMachine.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

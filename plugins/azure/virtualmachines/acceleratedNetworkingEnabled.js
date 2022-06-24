var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Accelerated Networking Enabled',
    category: 'Virtual Machines',
    domain: 'Compute',
    description: 'Ensures that accelerated networking is enabled on Azure virtual machines(VM).',
    more_info: 'Accelerated networking enables single root I/O virtualization (SR-IOV) to a VM, greatly improving its networking performance.',
    recommended_action: 'Enable accelerated networking in virtual machine network interfaces',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-network/create-vm-accelerated-networking-powershell',
    apis: ['virtualMachines:listAll', 'networkInterfaces:listAll'],

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

            var networkInterfaces = helpers.addSource(cache, source,
                ['networkInterfaces', 'listAll', location]);

            if (!networkInterfaces || networkInterfaces.err || !networkInterfaces.data || !networkInterfaces.data.length) {
                helpers.addResult(results, 3, 'Unable to query for network interfaces: ' + helpers.addError(networkInterfaces), location);
                return rcb();
            }

            const nicMap = new Map();
            networkInterfaces.data.forEach(networkInterface => {
                nicMap.set(networkInterface.id, networkInterface.enableAcceleratedNetworking);
            });

            virtualMachines.data.forEach(virtualMachine => {
                let acclNetwrork = false;
                if (virtualMachine.networkProfile && virtualMachine.networkProfile.networkInterfaces &&
                    virtualMachine.networkProfile.networkInterfaces.length > 0) {
                    acclNetwrork = virtualMachine.networkProfile.networkInterfaces.find(interface => {
                        if (nicMap.get(interface.id)) {
                            return true;
                        }
                    });
                }

                if (acclNetwrork) {
                    helpers.addResult(results, 0, 'Accelerated Networking is enabled on Azure Virtual Machine(VM)', location, virtualMachine.id);
                } else {
                    helpers.addResult(results, 2, 'Accelerated Networking is not enabled on Azure Virtual Machine(VM)', location, virtualMachine.id);
                }
            });
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
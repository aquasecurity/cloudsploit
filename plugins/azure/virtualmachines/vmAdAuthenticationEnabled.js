var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'VM Active Directory (AD) Authentication Enabled',
    category: 'Virtual Machines',
    description: 'Ensures that Azure Active Directory (AD) authentication is enabled for virtual machines.',
    more_info: 'Organizations can now improve the security of virtual machines (VMs) in Azure by integrating with Azure Active Directory (AD) authentication. Enabling Azure Active Directory (AD) authentication for Azure virtual machines (VMs) ensures access to VMs from one central point and simplifies access permission management.',
    recommended_action: 'Enable Azure Active Directory (AD) authentication for Azure virtual machines',
    link: 'https://docs.microsoft.com/en-us/azure/active-directory/devices/howto-vm-sign-in-azure-ad-windows',
    apis: ['virtualMachines:listAll', 'virtualMachineExtensions:list'],

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
                helpers.addResult(results, 0, 'No Virtual Machines found', location);
                return rcb();
            }

            async.each(virtualMachines.data, function(virtualMachine, scb) {
                const virtualMachineExtensions = helpers.addSource(cache, source,
                    ['virtualMachineExtensions', 'list', location, virtualMachine.id]);

                if (!virtualMachineExtensions || virtualMachineExtensions.err || !virtualMachineExtensions.data) {
                    helpers.addResult(results, 3, 'Unable to query for VM Extensions: ' + helpers.addError(virtualMachineExtensions), location, virtualMachine.id);
                    return scb();
                }

                if (!virtualMachineExtensions.data.length) {
                    helpers.addResult(results, 2, 'Azure Active Directory (AD) authentication is disabled for the virtual machine', location, virtualMachine.id);
                    return scb();
                }

                var windowsImg = false;
                if ((virtualMachine.storageProfile &&
                    virtualMachine.storageProfile.imageReference &&
                    virtualMachine.storageProfile.imageReference.offer &&
                    virtualMachine.storageProfile.imageReference.offer.toLowerCase().indexOf('windowsserver') > -1) || 
                    (virtualMachine.storageProfile &&
                    virtualMachine.storageProfile.osDisk &&
                    virtualMachine.storageProfile.osDisk.osType &&
                    virtualMachine.storageProfile.osDisk.osType.toLowerCase().indexOf('windows') > -1)) {
                    windowsImg = true;
                }

                const adEnabled = virtualMachineExtensions.data.some((virtualMachineExtension) => ((windowsImg && virtualMachineExtension.name && virtualMachineExtension.name === 'AADLoginForWindows') ||
                        (!windowsImg && virtualMachineExtension.name && virtualMachineExtension.name === 'AADLoginForLinux') ||
                        (!windowsImg && virtualMachineExtension.name && virtualMachineExtension.name === 'AADSSHLoginForLinux')));

                if (adEnabled) {
                    helpers.addResult(results, 0, 'Azure Active Directory (AD) authentication is enabled for the virtual machine', location, virtualMachine.id);
                } else {
                    helpers.addResult(results, 2, 'Azure Active Directory (AD) authentication is disabled for the virtual machine', location, virtualMachine.id);
                }

                scb();
            }, function() {
                rcb();
            });
        }, function() {
            callback(null, results, source);
        });
    }
};
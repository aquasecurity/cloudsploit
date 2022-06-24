var async = require('async');

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Virtual Machine Performance Diagnostics Enabled',
    category: 'Virtual Machines',
    domain: 'Compute',
    description: 'Ensures that performance diagnostics is enabled on virtual machines.',
    more_info: 'The performance diagnostics tool helps in troubleshooting performance issues that can affect a Windows or Linux virtual machine (VM).',
    recommended_action: 'Enable performance diagnostics on Azure virtual machines',
    link: 'https://docs.microsoft.com/en-us/troubleshoot/azure/virtual-machines/performance-diagnostics',
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
                    helpers.addResult(results, 2, 'Performance Diagnostics is disabled on the virtual machine', location, virtualMachine.id);
                    return scb();
                }

                var windowsImg = false;
                if ((virtualMachine.storageProfile &&
                    virtualMachine.storageProfile.imageReference &&
                    virtualMachine.storageProfile.imageReference.offer &&
                    virtualMachine.storageProfile.imageReference.offer.toLowerCase().indexOf('windowsserver') > -1) || (virtualMachine.storageProfile &&
                    virtualMachine.storageProfile.osDisk &&
                    virtualMachine.storageProfile.osDisk.osType &&
                    virtualMachine.storageProfile.osDisk.osType.toLowerCase().indexOf('windows') > -1)) {
                    windowsImg = true;
                }

                const adEnabled = virtualMachineExtensions.data.some((virtualMachineExtension) => (((windowsImg && virtualMachineExtension.name && virtualMachineExtension.name === 'AzurePerformanceDiagnostics') ||
                        (!windowsImg && virtualMachineExtension.name && virtualMachineExtension.name === 'AzurePerformanceDiagnosticsLinux')) && 
                        (virtualMachineExtension.provisioningState && virtualMachineExtension.provisioningState === 'Succeeded')));

                if (adEnabled) {
                    helpers.addResult(results, 0, 'Performance Diagnostics is enabled on the virtual machine', location, virtualMachine.id);
                } else {
                    helpers.addResult(results, 2, 'Performance Diagnostics is disabled on the virtual machine', location, virtualMachine.id);
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
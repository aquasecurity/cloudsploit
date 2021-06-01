var async = require('async');

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Virtual Machine Boot Diagnostics Enabled',
    category: 'Virtual Machines',
    description: 'Ensures that the VM boot diagnostics is enabled for virtual machines.',
    more_info: 'Boot diagnostics is a debugging feature for Azure virtual machines (VM) that allows diagnosis of VM boot failures. Boot diagnostics enables a user to observe the state of their VM as it is booting up by collecting serial log information and screenshots.',
    recommended_action: 'Enable boot diagnostics for all virtual machines.',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-machines/boot-diagnostics',
    apis: ['virtualMachines:listAll'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.virtualMachines, function(location, rcb){

            var virtualMachines = helpers.addSource(cache, source, ['virtualMachines', 'listAll', location]);

            if (!virtualMachines) return rcb();

            if (virtualMachines.err || !virtualMachines.data) {
                helpers.addResult(results, 3, 'Unable to query for Virtual Machines: ' + helpers.addError(virtualMachines), location);
                return rcb();
            }
            if (!virtualMachines.data.length) {
                helpers.addResult(results, 0, 'No existing virtual machines found', location);
                return rcb();
            }

            virtualMachines.data.forEach(virtualMachine => {
                if (virtualMachine.diagnosticsProfile && virtualMachine.diagnosticsProfile.bootDiagnostics && 
                    virtualMachine.diagnosticsProfile.bootDiagnostics.enabled) {
                    helpers.addResult(results, 0, 'Virtual machine has boot diagnostics enabled', location, virtualMachine.id);
                } else {
                    helpers.addResult(results, 2, 'Virtual machine does not have boot diagnostics enabled', location, virtualMachine.id);
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};